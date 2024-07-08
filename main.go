package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	"github.com/lib/pq"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB     *sql.DB
	JWTKey []byte
}

type Credentials struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Project struct {
	XataID          string   `json:"xata_id,omitempty"`          // Xata ID field
	UserID          string   `json:"user,omitempty"`             // User ID field
	Name            string   `json:"name,omitempty"`             // Project name
	RepoURL         string   `json:"repo_url,omitempty"`         // Repository URL
	SiteURL         string   `json:"site_url,omitempty"`         // Site URL
	Description     string   `json:"description,omitempty"`      // Project description
	Dependencies    []string `json:"dependencies,omitempty"`     // Project dependencies
	DevDependencies []string `json:"dev_dependencies,omitempty"` // Project dev dependencies
	Status          string   `json:"status,omitempty"`           // Project status
}

type Claims struct {
	Username string `json:"username"`
	Xata_ID  string `json:"xata_id"`
	jwt.RegisteredClaims
}

type UserResponse struct {
	Xata_ID  string `json:"xata_id"`
	Username string `json:"username"`
	Token    string `json:"token"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type RouteResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Err loading .env file")
	}

	var loadErr error
	userSchema, loadErr := loadSchema("schemas/user.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}

	projectSchema, loadErr := loadSchema("schemas/project.json")
	if loadErr != nil {
		log.Fatalf("Error loading user schema: %v", loadErr)
	}

	connStr := os.Getenv("XATA_PSQL_URL")
	if len(connStr) == 0 {
		log.Fatal("XATA_PSQL_URL environment variable is not set")
	}

	JWTKey := []byte(os.Getenv("JWT_SECRET"))
	if len(connStr) == 0 {
		log.Fatal("JWTKey environment variable is not set")
	}

	DB, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	defer DB.Close()

	app := &App{DB: DB, JWTKey: JWTKey}

	log.Println("Starting server...")

	router := *mux.NewRouter()

	log.Println("Setting up routes...")

	// Middleware chain and routes for user auth
	userChain := alice.New(loggingMiddleware, validateMiddleware(userSchema))
	router.Handle("/register", userChain.ThenFunc(app.register)).Methods("POST")
	router.Handle("/login", userChain.ThenFunc(app.login)).Methods("POST")

	// Middleware chain and routes for all projects requests that do not require a request body
	projectChain := alice.New(loggingMiddleware, app.jwtMiddleWare)
	router.Handle("/projects", projectChain.ThenFunc(app.getProjects)).Methods("GET")
	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.getProject)).Methods("GET")
	router.Handle("/projects/{xata_id}", projectChain.ThenFunc(app.deleteProject)).Methods("DELETE")

	// Middleware chain and routes for projects that require a request body
	projectChainWithValidation := projectChain.Append(validateMiddleware(projectSchema))
	router.Handle("/projects", projectChainWithValidation.ThenFunc(app.createProject)).Methods("POST")
	router.Handle("/projects/{xata_id}", projectChainWithValidation.ThenFunc(app.updateProject)).Methods("PUT")

	log.Println("Listening on port 5000")
	log.Fatal(http.ListenAndServe(":5000", &router))
}

// loadSchema loads a JSON schema from a file
func loadSchema(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (app *App) jwtMiddleWare(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			respondWithError(w, http.StatusBadRequest, "No token provided")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return app.JWTKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				respondWithError(w, http.StatusUnauthorized, "Invalid token signature")
				return
			}
			respondWithError(w, http.StatusBadRequest, "Invalid token")
			return
		}

		if !token.Valid {
			respondWithError(w, http.StatusBadRequest, "Invalid request payload")
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func validateMiddleware(schema string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			var body map[string]interface{}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}

			err = json.Unmarshal(bodyBytes, &body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid request payload")
				return
			}

			schemaLoader := gojsonschema.NewStringLoader(schema)

			documentLoader := gojsonschema.NewGoLoader(body)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Error validating JSON")
				return
			}

			if !result.Valid() {
				var errs []string
				for _, err := range result.Errors() {
					errs = append(errs, err.String())
				}
				respondWithError(w, http.StatusBadRequest, strings.Join(errs, ", "))
				return
			}

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			next.ServeHTTP(w, r)
		})
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Message: message})
}

func (app *App) generateToken(username, xataID string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)

	claims := &Claims{
		Username: username,
		Xata_ID:  xataID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(app.JWTKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// register function to handle user registration
func (app *App) register(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error hashing password")
		return
	}

	var xataID string
	err = app.DB.QueryRow(
		"INSERT INTO \"users\" (username, password) VALUES ($1, $2) RETURNING xata_id",
		creds.Username,
		string(hashedPassword),
	).Scan(&xataID)

	if err != nil {
		log.Println("Error details:", err)
		respondWithError(w, http.StatusInternalServerError, "Error creating user")
		return
	}

	tokenString, err := app.generateToken(creds.Username, xataID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{Xata_ID: xataID, Username: creds.Username, Token: tokenString})
}

// login
func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var storedCreds Credentials
	var xataID string

	err = app.DB.QueryRow("SELECT xata_id, username, password FROM \"users\" WHERE username=$1", creds.
		Username).Scan(&xataID, &storedCreds.Username, &storedCreds.Password)

	if err != nil {
		if err != sql.ErrNoRows {
			respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
			return
		}
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password))

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	tokenString, err := app.generateToken(creds.Username, xataID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error generating token")
		return
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(UserResponse{Xata_ID: xataID, Username: creds.Username, Token: tokenString})
}

// createProject
func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Invalid request payload")
		return
	}

	claims := r.Context().Value("claims").(*Claims)
	userID := claims.Xata_ID

	var xataID string
	err = app.DB.QueryRow(
		"INSERT INTO projects (\"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING xata_id",
		userID, project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status,
	).Scan(&xataID)
	if err != nil {
		log.Println(err)
		respondWithError(w, http.StatusInternalServerError, "Error creating project")
		return
	}

	project.XataID = xataID
	project.UserID = userID

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// updateProject
func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	xataID := vars["xata_id"]

	var project Project

	err := json.NewDecoder(r.Body).Decode(&project)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Invalid request payload")
		return
	}

	claims := r.Context().Value("claims").(*Claims)
	userID := claims.Xata_ID

	var storedID string
	err = app.DB.QueryRow("SELECT \"user\" FROM projects WHERE xata_id=$1", xataID).Scan(&storedID)

	if err != nil {
		log.Println(err)
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Project not found")
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Error fetching project")
		return
	}

	if storedID != userID {
		log.Printf("storedID: %s  userID: %s", storedID, userID)
		respondWithError(w, http.StatusForbidden, "You do not have permission to update this project")
		return
	}

	_, err = app.DB.Exec(
		`UPDATE projects SET name=$1, repo_url=$2, site_url=$3, description=$4, dependencies=$5, dev_dependencies=$6, status=$7 WHERE xata_id=$8 AND "user"=$9`,
		project.Name, project.RepoURL, project.SiteURL, project.Description, pq.Array(project.Dependencies), pq.Array(project.DevDependencies), project.Status, xataID, userID,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error updating project")
		return
	}
	fmt.Println(project.UserID, project.XataID)
	fmt.Println(userID, xataID)
	project.XataID = xataID
	project.UserID = userID

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// getProjects handles getting all of a specific users' project
func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {

	claims := r.Context().Value("claims").(*Claims)
	userID := claims.Xata_ID

	rows, err := app.DB.Query("SELECT xata_id, \"user\", name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE \"user\" =$1",
		userID)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error fetching projects")
		return
	}
	defer rows.Close()

	var projects []Project
	for rows.Next() {
		var project Project
		var dependencies, devDependencies []string

		err := rows.Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)
		if err != nil {
			log.Println(err)
			respondWithError(w, http.StatusInternalServerError, "Error scanning projects")
			return
		}

		project.Dependencies = dependencies
		project.DevDependencies = devDependencies

		projects = append(projects, project)
	}

	err = rows.Err()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error fetching projects")
		return
	}

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(projects)
}

// getProject
func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	xata_id := vars["xata_id"]

	claims := r.Context().Value("claims").(*Claims)
	userID := claims.Xata_ID

	var project Project

	var dependencies, devDependencies []string

	err := app.DB.QueryRow("SELECT xata_id, user, name, repo_url, site_url, description, dependencies, dev_dependencies, status FROM projects WHERE \"user\"=$1 AND xata_id=$2;",
		userID, xata_id).
		Scan(&project.XataID, &project.UserID, &project.Name, &project.RepoURL, &project.SiteURL, &project.Description, pq.Array(&dependencies), pq.Array(&devDependencies), &project.Status)

	if err != nil {
		log.Println(err)
		if err == sql.ErrNoRows {
			respondWithError(w, http.StatusNotFound, "Project not found")
			return
		}
		respondWithError(w, http.StatusNotFound, "Error fetching project")
		return
	}

	project.Dependencies = dependencies
	project.DevDependencies = devDependencies

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(project)
}

// deleteProject
func (app *App) deleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	claims := r.Context().Value("claims").(*Claims)
	userID := claims.Xata_ID

	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(RouteResponse{Message: "hello from deleteProject", ID: id})
}
