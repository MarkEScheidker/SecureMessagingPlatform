package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	baseURL        = "http://localhost:8000"
	keySize        = 2048
	privateKeyFile = "private_key.pem"
	publicKeyFile  = "public_key.pem"
)

// Client represents the chat client
type Client struct {
	username   string
	password   string
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	httpClient *http.Client
	hub        *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
	// keysDir    string
}

// NewClient creates a new chat client
func NewClient() *Client {
	// homeDir, _ := os.UserHomeDir()
	// keysDir := filepath.Join(homeDir, ".chat_keys")
	// os.MkdirAll(keysDir, 0700)

	return &Client{
		httpClient: &http.Client{},
	}
}

// AccountCreate represents account creation request
type AccountCreate struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// KeyRegister represents key registration request
type KeyRegister struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"public_key"`
}

// PublicKey represents the public key response
type PublicKey struct {
	Username   string `json:"username"`
	PublicKey  string `json:"public_key"`
	KeyVersion int    `json:"key_version"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Detail string `json:"detail"`
}

// generateKeyPair generates a new RSA key pair
func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// publicKeyToPEM converts public key to PEM format
func publicKeyToPEM(key *rsa.PublicKey) ([]byte, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return publicKeyPEM, nil
}

// pemToPublicKey converts PEM to public key
func pemToPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return publicKey, nil
}

// generateAndSaveKeys generates a new key pair and saves it in memory
func (c *Client) generateEphimerialKeys() error {
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %v", err)
	}

	// // Save private key
	// privateKeyPath := filepath.Join(c.keysDir, fmt.Sprintf("%s_%s", c.username, privateKeyFile))
	// privateKeyPEM := privateKeyToPEM(privateKey)
	// if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
	// 	return fmt.Errorf("failed to save private key: %v", err)
	// }

	// // Save public key
	// publicKeyPath := filepath.Join(c.keysDir, fmt.Sprintf("%s_%s", c.username, publicKeyFile))
	// publicKeyPEM, err := publicKeyToPEM(publicKey)
	// if err != nil {
	// 	return fmt.Errorf("failed to encode public key: %v", err)
	// }
	// if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
	// 	return fmt.Errorf("failed to save public key: %v", err)
	// }

	c.privateKey = privateKey
	c.publicKey = publicKey

	// fmt.Printf("Keys generated and saved to: %s\n", c.keysDir)
	return nil
}

// // loadKeys loads keys from disk
// func (c *Client) loadKey(keyFile, keyType string) error {
// 	if c.username == "" {
// 		return fmt.Errorf("not logged in")
// 	}

// 	privateKeyPath := filepath.Join(c.keysDir, fmt.Sprintf("%s_%s", c.username, privateKeyFile))
// 	publicKeyPath := filepath.Join(c.keysDir, fmt.Sprintf("%s_%s", c.username, publicKeyFile))

// 	// Load private key

// 	privateKeyPEM, err := os.ReadFile(privateKeyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read private key: %v", err)
// 	}
// 	privateKey, err := pemToPrivateKey(privateKeyPEM)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse private key: %v", err)
// 	}

// 	// Load public key
// 	publicKeyPEM, err := os.ReadFile(publicKeyPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read public key: %v", err)
// 	}
// 	publicKey, err := pemToPublicKey(publicKeyPEM)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse public key: %v", err)
// 	}

// 	c.privateKey = privateKey
// 	c.publicKey = publicKey

// 	fmt.Println("Keys loaded successfully")
// 	return nil
// }

// getPublicKeyString returns the public key as a PEM string
func (c *Client) getPublicKeyString() (string, error) {
	if c.publicKey == nil {
		return "", fmt.Errorf("no public key loaded")
	}
	publicKeyPEM, err := publicKeyToPEM(c.publicKey)
	if err != nil {
		return "", err
	}
	return string(publicKeyPEM), nil
}

// makeRequest makes an HTTP request and handles errors
func (c *Client) makeRequest(method, url string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, 0, err
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	return respBody, resp.StatusCode, nil
}

// createAccount creates a new account
func (c *Client) createAccount(username, password string) error {
	payload := AccountCreate{
		Username: username,
		Password: password,
	}

	respBody, statusCode, err := c.makeRequest("POST", baseURL+"/account/create", payload)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusCreated {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return fmt.Errorf("failed to create account: %s", errResp.Detail)
		}
		return fmt.Errorf("failed to create account: status %d", statusCode)
	}

	c.username = username
	c.password = password
	return nil
}

// registerKey registers a public key for the user
func (c *Client) registerKey(publicKey string) error {
	if c.username == "" || c.password == "" {
		return fmt.Errorf("not logged in")
	}

	payload := KeyRegister{
		Username:  c.username,
		Password:  c.password,
		PublicKey: publicKey,
	}

	respBody, statusCode, err := c.makeRequest("POST", baseURL+"/account/updatekey", payload)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return fmt.Errorf("failed to register key: %s", errResp.Detail)
		}
		return fmt.Errorf("failed to register key: status %d", statusCode)
	}

	return nil
}

// getKey retrieves a user's public key
func (c *Client) getKey(username string) (*PublicKey, error) {
	url := fmt.Sprintf("%s/keys/%s", baseURL, username)
	respBody, statusCode, err := c.makeRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}

	if statusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("failed to get key: %s", errResp.Detail)
		}
		return nil, fmt.Errorf("failed to get key: status %d", statusCode)
	}

	var pubKey PublicKey
	if err := json.Unmarshal(respBody, &pubKey); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &pubKey, nil
}

// login simulates logging in by storing credentials
func (c *Client) login(username, password string) error {
	c.username = username
	c.password = password

	accountCreateErr := c.createAccount(username, password)
	if accountCreateErr != nil {
		return accountCreateErr
	}
	// Try to load existing keys
	if err := c.generateEphimerialKeys(); err != nil {
		fmt.Println("Failed to generate keys:", err)
		return err
	}
	keyStr, err := c.getPublicKeyString()
	if err != nil {
		return fmt.Errorf("failed to get public key: %v", err)
	}

	return c.registerKey(keyStr)
}

// encryptWithPublicKey encrypts a message using RSA-OAEP and returns base64 string
func encryptWithPublicKey(pub *rsa.PublicKey, msg []byte) (string, error) {
	hash := sha256.New()
	cipherBytes, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// decryptWithPrivateKey decrypts a base64 RSA-OAEP encrypted message
func decryptWithPrivateKey(priv *rsa.PrivateKey, b64 string) (string, error) {
	cipherBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	plain, err := rsa.DecryptOAEP(hash, rand.Reader, priv, cipherBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// serve starts a TCP listener on the given port and accepts incoming chat connections.
// Each incoming connection is handled in its own goroutine.
func (c *Client) serve(port string, wg *sync.WaitGroup) error {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	fmt.Printf("Listening on %s\n", ln.Addr().String())

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("accept error:", err)
				continue
			}
			go c.handleConn(conn)
		}
	}()

	return nil
}

// handleConn handles a single incoming connection and reads JSON lines:
// {"from":"username","message":"<base64-cipher>"}
func (c *Client) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Println("read error:", err)
			}
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var pkt struct {
			From    string `json:"from"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(line), &pkt); err != nil {
			log.Println("invalid message format:", err)
			continue
		}
		if c.privateKey == nil {
			log.Println("received message but no private key loaded")
			continue
		}
		plain, err := decryptWithPrivateKey(c.privateKey, pkt.Message)
		if err != nil {
			log.Println("failed to decrypt message:", err)
			continue
		}
		fmt.Printf("\n[%s] %s\n", pkt.From, plain)
	}
}

// connectAndChat connects to address (host:port), fetches the recipient's public key using getKey(username),
// then enters an interactive loop: stdin lines are encrypted and sent; /quit to exit.
func (c *Client) connectAndChat(username, address string) error {
	if c.privateKey == nil {
		return fmt.Errorf("load keys first")
	}
	// fetch remote public key from server
	pubResp, err := c.getKey(username)
	if err != nil {
		return fmt.Errorf("failed to get public key for %s: %v", username, err)
	}

	remotePub, err := pemToPublicKey([]byte(pubResp.PublicKey))
	if err != nil {
		return fmt.Errorf("failed to parse remote public key: %v", err)
	}

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	defer conn.Close()

	// start reader goroutine
	go func() {
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Println("read error:", err)
				}
				return
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var pkt struct {
				From    string `json:"from"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal([]byte(line), &pkt); err != nil {
				log.Println("invalid message format:", err)
				continue
			}
			if c.privateKey == nil {
				log.Println("received message but no private key loaded")
				continue
			}
			plain, err := decryptWithPrivateKey(c.privateKey, pkt.Message)
			if err != nil {
				log.Println("failed to decrypt message:", err)
				continue
			}
			fmt.Printf("\n[%s] %s\n", pkt.From, plain)
		}
	}()

	fmt.Printf("Connected to %s. Type messages and press Enter. Type /quit to exit.\n", address)
	stdin := bufio.NewScanner(os.Stdin)
	for {
		if !stdin.Scan() {
			break
		}
		text := stdin.Text()
		if strings.TrimSpace(text) == "/quit" {
			break
		}
		cipherText, err := encryptWithPublicKey(remotePub, []byte(text))
		if err != nil {
			fmt.Printf("Encryption error: %v\n", err)
			continue
		}
		pkt := map[string]string{
			"from":    c.username,
			"message": cipherText,
		}
		out, _ := json.Marshal(pkt)
		_, err = conn.Write(append(out, '\n'))
		if err != nil {
			fmt.Printf("Send error: %v\n", err)
			break
		}
	}

	return nil
}

func printHelp() {
	fmt.Println("\nAvailable commands:")
	fmt.Println("  register <username> <password> - Create a new account")
	fmt.Println("  login <username> <password>    - Login to existing account")
	fmt.Println("  showpubkey                     - Display your public key")
	fmt.Println("  getkey <username>              - Get a user's public key from server")
	fmt.Println("  whoami                         - Show current username")
	fmt.Println("  help                           - Show this help message")
	fmt.Println("  quit or exit                   - Exit the client")
	fmt.Println()
}

func RunClient() {
	client := NewClient()
	scanner := bufio.NewScanner(os.Stdin)
	var listenerWG sync.WaitGroup

	fmt.Println("=== Public Key Chat Client ===")
	fmt.Println("Type 'help' for available commands")
	fmt.Println()

	for {
		if client.username != "" {
			fmt.Printf("[%s]> ", client.username)
		} else {
			fmt.Print("> ")
		}

		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := parts[0]

		switch command {
		case "help":
			printHelp()

		case "register":
			if len(parts) != 3 {
				fmt.Println("Usage: register <username> <password>")
				continue
			}
			username, password := parts[1], parts[2]
			if err := client.createAccount(username, password); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Account created successfully! Logged in as %s\n", username)
			}

		case "login":
			if len(parts) != 3 {
				fmt.Println("Usage: login <username> <password>")
				continue
			}
			username, password := parts[1], parts[2]
			if err := client.login(username, password); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Logged in as %s\n", username)
			}
		case "showpubkey":
			pubKeyStr, err := client.getPublicKeyString()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Println("\nYour Public Key:")
				fmt.Println(pubKeyStr)
			}

		case "uploadkey":
			if client.username == "" {
				fmt.Println("Error: Please login first")
				continue
			}
			pubKeyStr, err := client.getPublicKeyString()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			if err := client.registerKey(pubKeyStr); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Println("Public key uploaded successfully!")
			}

		case "getkey":
			if len(parts) != 2 {
				fmt.Println("Usage: getkey <username>")
				continue
			}
			username := parts[1]
			pubKey, err := client.getKey(username)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("\nUsername: %s\n", pubKey.Username)
				fmt.Printf("Key Version: %d\n", pubKey.KeyVersion)
				fmt.Printf("Public Key:\n%s\n", pubKey.PublicKey)
			}

		case "serve":
			if len(parts) != 2 {
				fmt.Println("Usage: serve <port>")
				continue
			}
			if client.privateKey == nil {
				fmt.Println("Error: load or generate keys before starting server")
				continue
			}
			port := parts[1]
			if err := client.serve(port, &listenerWG); err != nil {
				fmt.Printf("Error starting listener: %v\n", err)
			}

		case "connect":
			if len(parts) != 3 {
				fmt.Println("Usage: connect <username> <host:port>")
				continue
			}
			if client.privateKey == nil {
				fmt.Println("Error: load or generate keys before connecting")
				continue
			}
			username := parts[1]
			addr := parts[2]
			if err := client.connectAndChat(username, addr); err != nil {
				fmt.Printf("Error: %v\n", err)
			}

		case "whoami":
			if client.username != "" {
				fmt.Printf("Logged in as: %s\n", client.username)
				if client.publicKey != nil {
					fmt.Println("Keys loaded: Yes")
				} else {
					fmt.Println("Keys loaded: No")
				}
			} else {
				fmt.Println("Not logged in")
			}

		case "quit", "exit":
			fmt.Println("Goodbye!")
			// allow listener goroutines to finish (they run until program exit)
			return

		default:
			fmt.Printf("Unknown command: %s (type 'help' for available commands)\n", command)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}

// serveWs handles websocket requests from the peer.
func ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	// Allow collection of memory referenced by the caller by doing all work in
	// new goroutines.
	go client.writePump()
	go client.readPump()
}

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// readPump pumps messages from the websocket connection to the hub.
//
// The application runs readPump in a per-connection goroutine. The application
// ensures that there is at most one reader on a connection by executing all
// reads from this goroutine.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
		c.hub.broadcast <- message
	}
}

// writePump pumps messages from the hub to the websocket connection.
//
// A goroutine running writePump is started for each connection. The
// application ensures that there is at most one writer to a connection by
// executing all writes from this goroutine.
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued chat messages to the current websocket message.
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write(newline)
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}

// Hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*Client]bool

	// Inbound messages from the clients.
	broadcast chan []byte

	// Register requests from the clients.
	register chan *Client

	// Unregister requests from clients.
	unregister chan *Client
}

func NewHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		clients:    make(map[*Client]bool),
	}
}
