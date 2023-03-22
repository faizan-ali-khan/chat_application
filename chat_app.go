package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// User represents a user account.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// ChatRoom represents a chat room.
type ChatRoom struct {
	ID       string
	Name     string
	Users    map[int]*websocket.Conn
	Messages []*Message
}

// Message represents a chat message.
type Message struct {
	ID        int       `json:"id"`
	UserID    int       `json:"userId"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// Globals
var (
	db         = make(map[int]User)
	chatRooms  = make(map[string]*ChatRoom)
	messageID  = 0
	upgrader   = websocket.Upgrader{}
)

func main() {
	// Create a new Gorilla Mux router
	r := mux.NewRouter()

	// Define the HTTP routes
	r.HandleFunc("/register", handleUserRegistration).Methods("POST")
	r.HandleFunc("/login", handleUserLogin).Methods("POST")
	r.HandleFunc("/chatroom/{id}", handleChatRoom).Methods("GET")

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(":8000", r))
}

func handleUserRegistration(w http.ResponseWriter, r *http.Request) {
	// Parse the request body to get the user data
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Assign an ID to the user
	user.ID = len(db) + 1

	// Hash the user's password before storing it in the database
	// In production, use a more secure hashing algorithm and store the salt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Store the user in the database
	db[user.ID] = user

	// Return the user data as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func handleUserLogin(w http.ResponseWriter, r *http.Request) {
	// Parse the request body to get the user credentials
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Find the user in the database by username
	var user *User
	for _, u := range db {
		if u.Username == credentials.Username {
			user = &u
			break
		}
	}
	if user == nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Check the password hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Return the user
	// Create a new WebSocket connection for the user
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the chat room ID from the URL path
	chatRoomID := mux.Vars(r)["id"]

	// Find the chat room by ID
	chatRoom, ok := chatRooms[chatRoomID]
	if !ok {
		http.Error(w, "Chat room not found", http.StatusNotFound)
		return
	}

	// Add the user's WebSocket connection to the chat room
	chatRoom.Users[user.ID] = conn

	// Send the chat room messages to the user
	for _, msg := range chatRoom.Messages {
		err = conn.WriteJSON(msg)
		if err != nil {
			log.Printf("Error sending message to user %d: %v", user.ID, err)
			continue
		}
	}

	// Listen for messages from the user
	for {
		// Read the message from the WebSocket connection
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			// Remove the user's WebSocket connection from the chat room
			delete(chatRoom.Users, user.ID)
			log.Printf("User %d disconnected from chat room %s", user.ID, chatRoomID)
			break
		}

		// Assign an ID to the message
		messageID++
		msg.ID = messageID

		// Set the message timestamp
		msg.Timestamp = time.Now()

		// Set the message user ID and username
		msg.UserID = user.ID
		msg.Username = user.Username

		// Add the message to the chat room
		chatRoom.Messages = append(chatRoom.Messages, &msg)

		// Send the message to all other users in the chat room
		for userID, conn := range chatRoom.Users {
			if userID != user.ID {
				err = conn.WriteJSON(msg)
				if err != nil {
					log.Printf("Error sending message to user %d: %v", userID, err)
					continue
				}
			}
		}
	}
}
