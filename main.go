package main

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type User struct {
	ID                           int
	Username, PasswordHash, Role string
}
type Note struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	OwnerID int    `json:"ownerId"`
}
type Claims struct {
	UserID int    `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}
type contextKey string

const userKey contextKey = "user"

var users []User
var notes []Note
var nextID int
var mutex sync.RWMutex
var secret []byte

func send(responseWriter http.ResponseWriter, status int, value any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	json.NewEncoder(responseWriter).Encode(value)
}

// Проверяем пароль по хешу и выдаём токен.
func login(responseWriter http.ResponseWriter, request *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(request.Body).Decode(&input) != nil {
		http.Error(responseWriter, "Invalid input", 400)
		return
	}
	for _, user := range users {
		if user.Username == input.Username && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) == nil {
			claims := Claims{UserID: user.ID, Role: user.Role, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute))}}
			token, operationError := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
			if operationError != nil {
				http.Error(responseWriter, "Server error", 500)
				return
			}
			send(responseWriter, 200, map[string]string{"access_token": token, "token_type": "Bearer"})
			return
		}
	}
	http.Error(responseWriter, "Invalid credentials", 401)
}

// Проверяем токен перед обращением к защищённым маршрутам.
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		parts := strings.Fields(request.Header.Get("Authorization"))
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(responseWriter, "Unauthorized", 401)
			return
		}
		claims := &Claims{}
		token, operationError := jwt.ParseWithClaims(parts[1], claims, func(receivedToken *jwt.Token) (any, error) { return secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
		if operationError != nil || !token.Valid || claims.UserID <= 0 || (claims.Role != "user" && claims.Role != "admin") {
			http.Error(responseWriter, "Unauthorized", 401)
			return
		}
		next(responseWriter, request.WithContext(context.WithValue(request.Context(), userKey, claims)))
	}
}

func list(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	mutex.RLock()
	defer mutex.RUnlock()
	result := []Note{}
	for _, note := range notes {
		if user.Role == "admin" || note.OwnerID == user.UserID {
			result = append(result, note)
		}
	}
	send(responseWriter, 200, result)
}

func create(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	var note Note
	if json.NewDecoder(request.Body).Decode(&note) != nil || strings.TrimSpace(note.Title) == "" || strings.TrimSpace(note.Content) == "" {
		http.Error(responseWriter, "Invalid note", 400)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	nextID = nextID + 1
	note.ID = nextID
	note.OwnerID = user.UserID
	notes = append(notes, note)
	send(responseWriter, 201, note)
}

func remove(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	if user.Role != "admin" {
		http.Error(responseWriter, "Forbidden", 403)
		return
	}
	id, operationError := strconv.Atoi(request.PathValue("id"))
	if operationError != nil || id <= 0 {
		http.Error(responseWriter, "Invalid ID", 400)
		return
	}
	mutex.Lock()
	defer mutex.Unlock()
	for index, note := range notes {
		if note.ID == id {
			notes = append(notes[:index], notes[index+1:]...)
			responseWriter.WriteHeader(204)
			return
		}
	}
	http.NotFound(responseWriter, request)
}

func main() {
	secret = []byte(os.Getenv("JWT_SECRET"))
	if len(secret) == 0 {
		log.Fatal("Set JWT_SECRET")
	}
	for index, user := range []struct {
		username string
		password string
		role     string
	}{
		{username: "student", password: "Student123!", role: "user"},
		{username: "admin", password: "Admin123!", role: "admin"},
	} {
		hash, operationError := bcrypt.GenerateFromPassword([]byte(user.password), bcrypt.DefaultCost)
		if operationError != nil {
			log.Fatal(operationError)
		}
		users = append(users, User{index + 1, user.username, string(hash), user.role})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/login", login)
	mux.HandleFunc("GET /notes", auth(list))
	mux.HandleFunc("POST /notes", auth(create))
	mux.HandleFunc("DELETE /notes/{id}", auth(remove))
	log.Println("http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
