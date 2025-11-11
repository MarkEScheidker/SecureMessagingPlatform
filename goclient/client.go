package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/chzyer/readline"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	defaultServer = "https://scheidker.com"
	protocolTag   = "smproto-v1"
)

type appState struct {
	username string
	password string
	server   string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
}

type session struct {
	role        string
	peer        string
	cipher      cipher.AEAD
	transcript  []byte
	sendCounter uint64
	recvCounter int64
}

type wsClient struct {
	conn     *websocket.Conn
	incoming chan map[string]interface{}
	mu       sync.Mutex
	pending  []map[string]interface{}
}

var errWaitCancelled = errors.New("wait cancelled")

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	reader := bufio.NewReader(os.Stdin)
	username := prompt(reader, "Username: ")
	password := prompt(reader, "Password: ")
	if password == "" {
		return errors.New("password cannot be empty")
	}

	var server string
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if os.Getenv("SMSERVER_HOST") == "" {
		server = defaultServer

	} else {
		server = os.Getenv("SMSERVER_HOST")
	}
	state := &appState{
		username: username,
		password: password,
		server:   server,
		priv:     priv,
		pub:      pub,
	}

	if err := publishKey(state); err != nil {
		return err
	}
	fmt.Println("[key-server] identity stored.")

	wsURL, err := buildWSURL(state.server, state.username)
	if err != nil {
		return err
	}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := newWSClient(conn)

	for {
		peer, err := promptPeer(reader)
		if err != nil {
			return err
		}
		sess, err := connectPeer(client, state, peer)
		if err != nil {
			if errors.Is(err, errWaitCancelled) {
				continue
			}
			fmt.Printf("[connect] %v\n", err)
			continue
		}
		chat(client, sess)
		reader = bufio.NewReader(os.Stdin)
	}
}

func promptPeer(reader *bufio.Reader) (string, error) {
	for {
		fmt.Print("Connect to username: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		peer := strings.TrimSpace(line)
		if peer != "" {
			return peer, nil
		}
	}
}

func newWSClient(conn *websocket.Conn) *wsClient {
	c := &wsClient{
		conn:     conn,
		incoming: make(chan map[string]interface{}, 8),
	}
	go func() {
		for {
			var msg map[string]interface{}
			if err := conn.ReadJSON(&msg); err != nil {
				close(c.incoming)
				return
			}
			c.incoming <- msg
		}
	}()
	return c
}

func (c *wsClient) stashMessage(msg map[string]interface{}) {
	if msg == nil {
		return
	}
	c.mu.Lock()
	c.pending = append(c.pending, msg)
	c.mu.Unlock()
}

func (c *wsClient) takePending(match func(map[string]interface{}) bool) (map[string]interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pending) == 0 {
		return nil, false
	}
	if match == nil {
		msg := c.pending[0]
		c.pending = c.pending[1:]
		return msg, true
	}
	for i, msg := range c.pending {
		if match(msg) {
			c.pending = append(c.pending[:i], c.pending[i+1:]...)
			return msg, true
		}
	}
	return nil, false
}

func (c *wsClient) send(to, msgType string, payload interface{}) error {
	envelope := map[string]interface{}{
		"to":      to,
		"type":    msgType,
		"payload": payload,
	}
	return c.conn.WriteJSON(envelope)
}

func (c *wsClient) nextMessage() (map[string]interface{}, error) {
	if msg, ok := c.takePending(func(m map[string]interface{}) bool {
		return fmt.Sprint(m["type"]) != "handshake_init"
	}); ok {
		return msg, nil
	}
	msg, ok := <-c.incoming
	if !ok {
		return nil, errors.New("connection closed")
	}
	return msg, nil
}

func publishKey(state *appState) error {
	body, _ := json.Marshal(map[string]string{
		"username":   state.username,
		"password":   state.password,
		"public_key": base64.StdEncoding.EncodeToString(state.pub),
	})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(state.server, "/")+"/keys", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("key server returned %s", resp.Status)
	}
	return nil
}

func fetchKey(server, username string) ([]byte, int, error) {
	endpoint := strings.TrimRight(server, "/") + "/keys/" + url.PathEscape(username)
	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, 0, fmt.Errorf("lookup failed: %s", resp.Status)
	}
	var data struct {
		PublicKey  string `json:"public_key"`
		KeyVersion int    `json:"key_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, 0, err
	}
	pub, err := base64.StdEncoding.DecodeString(data.PublicKey)
	return pub, data.KeyVersion, err
}

func connectPeer(client *wsClient, state *appState, peer string) (*session, error) {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return nil, errors.New("peer cannot be empty")
	}
	if peer == state.username {
		return nil, errors.New("cannot chat with yourself")
	}
	if state.username < peer {
		return startSession(client, state, peer)
	}
	return waitForPeerSession(client, state, peer)
}

func startSession(client *wsClient, state *appState, peer string) (*session, error) {
	peerKey, version, err := fetchKey(state.server, peer)
	if err != nil {
		return nil, err
	}
	priv, pub, err := generateEphemeral()
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	payload := handshakePayload("init", state.username, peer, pub, nonce)
	sig := ed25519.Sign(state.priv, payload)
	msg := map[string]string{
		"username":  state.username,
		"target":    peer,
		"ephemeral": base64.StdEncoding.EncodeToString(pub),
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
	if err := client.send(peer, "handshake_init", msg); err != nil {
		return nil, err
	}
	for {
		msg, err := client.nextMessage()
		if err != nil {
			return nil, err
		}
		if msg["type"] != "handshake_accept" || msg["from"] != peer {
			continue
		}
		payload, _ := msg["payload"].(map[string]interface{})
		if payload == nil {
			fmt.Println("[connect] empty payload, ignoring")
			continue
		}
		sess, err := completeInitiator(state, peer, peerKey, priv, pub, nonce, payload)
		if err != nil {
			return nil, err
		}
		fmt.Printf("[session] connected to %s (key v%d)\n", peer, version)
		return sess, nil
	}
}

func waitForPeerSession(client *wsClient, state *appState, peer string) (*session, error) {
	fmt.Printf("Waiting for %s to connect...\n", peer)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	handleHandshake := func(msg map[string]interface{}) (*session, error) {
		if fmt.Sprint(msg["type"]) != "handshake_init" {
			return nil, nil
		}
		payload, _ := msg["payload"].(map[string]interface{})
		if payload == nil {
			return nil, nil
		}
		from := fmt.Sprint(msg["from"])
		if from != peer {
			client.stashMessage(msg)
			return nil, nil
		}
		sess, reply, version, err := acceptResponder(state, peer, payload)
		if err != nil {
			return nil, nil
		}
		if err := client.send(peer, "handshake_accept", reply); err != nil {
			return nil, err
		}
		fmt.Printf("[session] connected to %s (key v%d)\n", peer, version)
		return sess, nil
	}

	for {
		if msg, ok := client.takePending(func(m map[string]interface{}) bool {
			return fmt.Sprint(m["type"]) == "handshake_init" && fmt.Sprint(m["from"]) == peer
		}); ok {
			sess, err := handleHandshake(msg)
			if err != nil {
				return nil, err
			}
			if sess != nil {
				return sess, nil
			}
			continue
		}

		select {
		case <-sigCh:
			fmt.Println("\n[session] cancelled wait.")
			return nil, errWaitCancelled
		case msg, ok := <-client.incoming:
			if !ok {
				return nil, errors.New("connection closed")
			}
			sess, err := handleHandshake(msg)
			if err != nil {
				return nil, err
			}
			if sess != nil {
				return sess, nil
			}
		}
	}
}

func chat(client *wsClient, sess *session) {
	const promptLabel = "you> "
	fmt.Printf("Chatting with %s. Use /leave to exit.\n", sess.peer)

	cancelable := readline.NewCancelableStdin(readline.Stdin)
	rl, err := readline.NewEx(&readline.Config{
		Prompt: promptLabel,
		Stdin:  cancelable,
	})
	if err != nil {
		fmt.Printf("[chat] failed to initialize prompt: %v\n", err)
		return
	}

	input := make(chan string, 32)
	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		defer close(input)
		for {
			line, err := rl.Readline()
			if err == readline.ErrInterrupt {
				select {
				case input <- "/leave":
				case <-stop:
				}
				continue
			}
			if err != nil {
				return
			}
			select {
			case input <- line:
			case <-stop:
				return
			}
		}
	}()
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			close(stop)
			cancelable.Close()
			rl.Close()
			readerWG.Wait()
		})
	}
	defer cleanup()

	clearPrompt := func() {
		rl.Clean()
	}

	sentLeave := false
	notifyPeerLeave := func() {
		if sentLeave {
			return
		}
		sentLeave = true
		_ = client.send(sess.peer, "chat_leave", map[string]string{"reason": "peer_left"})
	}

	for {
		select {
		case line, ok := <-input:
			if !ok {
				notifyPeerLeave()
				clearPrompt()
				cleanup()
				fmt.Println("Session closed.")
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				rl.Refresh()
				continue
			}
			if line == "/leave" || line == "/quit" {
				notifyPeerLeave()
				clearPrompt()
				cleanup()
				fmt.Println("Session closed.")
				return
			}
			if err := sendChat(client, sess, line); err != nil {
				clearPrompt()
				cleanup()
				fmt.Printf("[chat] %v\n", err)
				return
			}
			rl.Refresh()
		case msg, ok := <-client.incoming:
			if !ok {
				clearPrompt()
				cleanup()
				fmt.Println("[relay] connection closed.")
				return
			}
			msgType := fmt.Sprint(msg["type"])
			switch {
			case msgType == "chat" && msg["from"] == sess.peer:
				if err := displayChat(sess, msg["payload"], rl.Stdout()); err != nil {
					clearPrompt()
					cleanup()
					fmt.Printf("[chat] %v\n", err)
					return
				}
				rl.Refresh()
			case msgType == "chat_leave" && msg["from"] == sess.peer:
				clearPrompt()
				cleanup()
				fmt.Printf("[session] %s left the chat.\n", sess.peer)
				return
			case strings.HasPrefix(msgType, "handshake_"):
				client.stashMessage(msg)
				fmt.Fprintf(rl.Stdout(), "[relay] %s from %v (queued)\n", msgType, msg["from"])
				rl.Refresh()
			default:
				fmt.Fprintf(rl.Stdout(), "[relay] %s from %v\n", msgType, msg["from"])
				rl.Refresh()
			}
		}
	}
}

func sendChat(client *wsClient, sess *session, text string) error {
	counter, ciphertext, err := sess.encrypt([]byte(text))
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"nonce":      counter,
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
	}
	return client.send(sess.peer, "chat", payload)
}

func displayChat(sess *session, payload interface{}, w io.Writer) error {
	data, _ := payload.(map[string]interface{})
	if data == nil {
		return errors.New("missing chat payload")
	}
	nonceFloat, _ := data["nonce"].(float64)
	ctString, _ := data["ciphertext"].(string)
	ciphertext, err := base64.StdEncoding.DecodeString(ctString)
	if err != nil {
		return err
	}
	plain, err := sess.decrypt(uint64(nonceFloat), ciphertext)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s> %s\n", sess.peer, string(plain))
	return nil
}

func completeInitiator(state *appState, peer string, peerKey []byte, ephPriv [32]byte, localEph []byte, localNonce []byte, payload map[string]interface{}) (*session, error) {
	if payload == nil {
		return nil, errors.New("missing payload")
	}
	nonceStr, _ := payload["nonce"].(string)
	ephStr, _ := payload["ephemeral"].(string)
	sigStr, _ := payload["signature"].(string)
	peerNonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return nil, err
	}
	peerEph, err := base64.StdEncoding.DecodeString(ephStr)
	if err != nil {
		return nil, err
	}
	peerSig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return nil, err
	}
	acceptPayload := handshakePayload("accept", peer, state.username, peerEph, peerNonce)
	if !ed25519.Verify(ed25519.PublicKey(peerKey), acceptPayload, peerSig) {
		return nil, errors.New("signature mismatch")
	}
	return deriveSession("initiator", state.username, peer, ephPriv, localEph, peerEph, localNonce, peerNonce)
}

func acceptResponder(state *appState, expected string, payload map[string]interface{}) (*session, map[string]string, int, error) {
	username, _ := payload["username"].(string)
	target, _ := payload["target"].(string)
	if username == "" || target != state.username || username != expected {
		return nil, nil, 0, errors.New("target mismatch")
	}
	nonceStr, _ := payload["nonce"].(string)
	ephStr, _ := payload["ephemeral"].(string)
	sigStr, _ := payload["signature"].(string)
	remoteNonce, err := base64.StdEncoding.DecodeString(nonceStr)
	if err != nil {
		return nil, nil, 0, err
	}
	remoteEph, err := base64.StdEncoding.DecodeString(ephStr)
	if err != nil {
		return nil, nil, 0, err
	}
	remoteSig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return nil, nil, 0, err
	}
	peerKey, version, err := fetchKey(state.server, username)
	if err != nil {
		return nil, nil, 0, err
	}
	initPayload := handshakePayload("init", username, state.username, remoteEph, remoteNonce)
	if !ed25519.Verify(ed25519.PublicKey(peerKey), initPayload, remoteSig) {
		return nil, nil, 0, errors.New("signature mismatch")
	}
	respPriv, respPub, err := generateEphemeral()
	if err != nil {
		return nil, nil, 0, err
	}
	localNonce, err := randomBytes(16)
	if err != nil {
		return nil, nil, 0, err
	}
	respPayload := handshakePayload("accept", state.username, username, respPub, localNonce)
	respSig := ed25519.Sign(state.priv, respPayload)
	sess, err := deriveSession("responder", state.username, username, respPriv, respPub, remoteEph, localNonce, remoteNonce)
	if err != nil {
		return nil, nil, 0, err
	}
	reply := map[string]string{
		"username":  state.username,
		"expected":  username,
		"ephemeral": base64.StdEncoding.EncodeToString(respPub),
		"nonce":     base64.StdEncoding.EncodeToString(localNonce),
		"signature": base64.StdEncoding.EncodeToString(respSig),
	}
	return sess, reply, version, nil
}

func deriveSession(role, username, peer string, priv [32]byte, localEph, remoteEph, localNonce, remoteNonce []byte) (*session, error) {
	shared, err := curve25519.X25519(priv[:], remoteEph)
	if err != nil {
		return nil, err
	}
	orderA, orderB := username, peer
	ephConcat := append(localEph, remoteEph...)
	nonceConcat := append(localNonce, remoteNonce...)
	if peer < username {
		orderA, orderB = peer, username
		ephConcat = append(remoteEph, localEph...)
		nonceConcat = append(remoteNonce, localNonce...)
	}
	transcript := bytes.Join([][]byte{
		[]byte(protocolTag),
		[]byte(orderA),
		[]byte(orderB),
		ephConcat,
		nonceConcat,
	}, []byte("|"))
	h := hkdf.New(sha256.New, shared, nil, transcript)
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &session{
		role:        role,
		peer:        peer,
		cipher:      aead,
		transcript:  transcript,
		sendCounter: 0,
		recvCounter: -1,
	}, nil
}

func (s *session) encrypt(plaintext []byte) (uint64, []byte, error) {
	nonce := buildNonce(s.role, s.sendCounter)
	counter := s.sendCounter
	s.sendCounter++
	ciphertext := s.cipher.Seal(nil, nonce, plaintext, s.transcript)
	return counter, ciphertext, nil
}

func (s *session) decrypt(counter uint64, ciphertext []byte) ([]byte, error) {
	if int64(counter) <= s.recvCounter {
		return nil, errors.New("replayed message")
	}
	peerRole := "responder"
	if s.role == "responder" {
		peerRole = "initiator"
	}
	nonce := buildNonce(peerRole, counter)
	plaintext, err := s.cipher.Open(nil, nonce, ciphertext, s.transcript)
	if err != nil {
		return nil, err
	}
	s.recvCounter = int64(counter)
	return plaintext, nil
}

func buildWSURL(base, username string) (string, error) {
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "http":
		parsed.Scheme = "ws"
	case "https":
		parsed.Scheme = "wss"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported scheme: %s", parsed.Scheme)
	}
	path := strings.TrimRight(parsed.Path, "/")
	if path == "" {
		path = "/ws"
	} else {
		path += "/ws"
	}
	parsed.Path = path
	q := parsed.Query()
	q.Set("username", username)
	parsed.RawQuery = q.Encode()
	return parsed.String(), nil
}

func prompt(reader *bufio.Reader, label string) string {
	for {
		fmt.Print(label)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text != "" {
			return text
		}
	}
}

func generateEphemeral() ([32]byte, []byte, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, nil, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	return priv, pub, err
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	return buf, err
}

func buildNonce(role string, counter uint64) []byte {
	buf := make([]byte, 12)
	if role == "initiator" {
		copy(buf, []byte("INIT"))
	} else {
		copy(buf, []byte("RESP"))
	}
	binary.BigEndian.PutUint64(buf[4:], counter)
	return buf
}

func handshakePayload(event, sender, receiver string, ephPub, nonce []byte) []byte {
	return bytes.Join([][]byte{
		[]byte(protocolTag),
		[]byte(event),
		[]byte(sender),
		[]byte(receiver),
		ephPub,
		nonce,
	}, []byte("|"))
}

func printEnvelope(msg map[string]interface{}) {
	fmt.Printf("[relay] %s from %v\n", msg["type"], msg["from"])
}
