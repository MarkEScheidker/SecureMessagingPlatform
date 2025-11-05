package securemessagingplatformServer

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MarkEScheidker/SecureMessagingPlatform/client"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// StoredUser represents a user with their password hash and public key
type StoredUser struct {
	PasswordHash string
	PublicKey    string
	KeyVersion   int
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

// StatusResponse represents a status response
type StatusResponse struct {
	Status  string `json:"status"`
	Service string `json:"service,omitempty"`
}

// KeyUpdateResponse represents a key update response
type KeyUpdateResponse struct {
	Status     string `json:"status"`
	KeyVersion int    `json:"key_version"`
}

// Server holds the application state
type Server struct {
	users map[string]*StoredUser
	mu    sync.RWMutex
}

// NewServer creates a new server instance
func NewServer() *Server {
	return &Server{
		users: make(map[string]*StoredUser),
	}
}

// hashPassword creates a bcrypt hash of the password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// checkPassword verifies a password against a hash
func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// validateUsername checks if username meets requirements
func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 32 || strings.Contains(username, " ") {
		return &HTTPError{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "Username must be 3-32 characters with no spaces.",
		}
	}
	return nil
}

// HTTPError represents an HTTP error with status code
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return e.Message
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func writeError(w http.ResponseWriter, statusCode int, message string) {
	writeJSON(w, statusCode, ErrorResponse{Detail: message})
}

// statusHandler returns service status
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, StatusResponse{
		Status:  "ok",
		Service: "public-key-server",
	})
}

// createAccountHandler handles account creation
func (s *Server) createAccountHandler(w http.ResponseWriter, r *http.Request) {
	var payload AccountCreate
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := validateUsername(payload.Username); err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			writeError(w, httpErr.StatusCode, httpErr.Message)
		}
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hash, err := hashPassword(payload.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}
	if user, exists := s.users[payload.Username]; exists {
		if user.PasswordHash != hash {
			writeError(w, http.StatusConflict, "Username or Password is incorrect.")
		}
		writeJSON(w, http.StatusCreated, StatusResponse{Status: "login"})
		return
	}

	s.users[payload.Username] = &StoredUser{
		PasswordHash: hash,
		PublicKey:    "",
		KeyVersion:   0,
	}

	writeJSON(w, http.StatusCreated, StatusResponse{Status: "created"})
}

// registerKeyHandler handles key registration
func (s *Server) registerKeyHandler(w http.ResponseWriter, r *http.Request) {
	var payload KeyRegister
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := validateUsername(payload.Username); err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			writeError(w, httpErr.StatusCode, httpErr.Message)
		}
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	user, exists := s.users[payload.Username]
	if !exists || !checkPassword(payload.Password, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "Invalid username or password.")
		return
	}

	cleanedKey := strings.TrimSpace(payload.PublicKey)
	if cleanedKey == "" {
		writeError(w, http.StatusUnprocessableEntity, "Public key cannot be empty.")
		return
	}

	user.PublicKey = cleanedKey
	user.KeyVersion++

	writeJSON(w, http.StatusOK, KeyUpdateResponse{
		Status:     "updated",
		KeyVersion: user.KeyVersion,
	})
}

// getKeyHandler retrieves a user's public key
func (s *Server) getKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	if err := validateUsername(username); err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			writeError(w, httpErr.StatusCode, httpErr.Message)
		}
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[username]
	if !exists || user.PublicKey == "" {
		writeError(w, http.StatusNotFound, "No key stored for that user.")
		return
	}

	writeJSON(w, http.StatusOK, PublicKey{
		Username:   username,
		PublicKey:  user.PublicKey,
		KeyVersion: user.KeyVersion,
	})
}

var addr = flag.String("addr", ":8080", "http service address")

func serveHome(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	if r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.ServeFile(w, r, "home.html")
}

func main() {
}

func RunServer() {
	flag.Parse()
	hub := client.NewHub()
	go hub.Run()
	http.HandleFunc("/", serveHome)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		client.ServeWs(hub, w, r)
	})
	server := NewServer()
	router := mux.NewRouter()

	router.HandleFunc("/status", server.statusHandler).Methods("GET")
	router.HandleFunc("/account/create", server.createAccountHandler).Methods("POST")
	router.HandleFunc("/account/updatekey", server.registerKeyHandler).Methods("POST")
	router.HandleFunc("/keys/{username}", server.getKeyHandler).Methods("GET")

	log.Println("Starting server on :8000")
	log.Fatal(http.ListenAndServe(":8000", router))
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

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
