package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	connStr       = "user=postgres dbname=postgres password=admin sslmode=disable"
	migrationsDir = "./migrations"
	adminPassword = "secretAdminPassword"
)

type Comment struct {
	Username  string    `json:"username"`
	CommentID int       `json:"comment_id"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Couldn't connect to the database: %v", err)
	}
	defer db.Close()

	if err := goose.Up(db, migrationsDir); err != nil {
		log.Fatalf("Migration trouble: %s", err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/comment", commentHandler).Methods("POST")
	r.HandleFunc("/delete", deleteHandler).Methods("POST")
	r.HandleFunc("/updateComments", updateCommentsHandler).Methods("GET")
	fmt.Println("Admin password: ", adminPassword)
	http.Handle("/", r)
	fmt.Println("Server is running on http://localhost:8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func updateCommentsHandler(w http.ResponseWriter, r *http.Request) {
	comments, err := getComments()
	if err != nil {
		http.Error(w, "Error retrieving comments: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonData, err := json.Marshal(comments)
	if err != nil {
		http.Error(w, "Couldn't marshal comments: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	comments, err := getComments()
	if err != nil {
		http.Error(w, "Error fetching comments: "+err.Error(), http.StatusInternalServerError)
		return
	}

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>4chan from aliexpress</title>
		<style>
			body {
				font-family: 'Comic Sans MS', 'Comic Neue', cursive, sans-serif;
				background-color: #F0E68C;
				margin: 0;
				padding: 0;
			}
			.container {
				width: 50%;
				margin: 0 auto;
				background-color: #FFF8DC;
				border: 3px solid #000000;
				padding: 20px;
				margin-top: 20px;
			}
			input[type="text"], input[type="password"], textarea {
				border: 2px solid #000000;
				background-color: #F5F5F5;
			}
			button {
				background-color: #8B0000;
				color: #FFFFFF;
				border: none;
				padding: 10px 20px;
				cursor: pointer;
			}
			button:hover {
				background-color: #B22222;
			}
			.comment {
				margin-bottom: 10px;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>20 most recent comments</h1>
			<div id="comments">`
	for _, comment := range comments {
		html += fmt.Sprintf("<div class='comment'><b>%s</b> (%s) [%d]: %s</div>",
			comment.Username, comment.Timestamp.Format("02.01.2006, 15:04:05"), comment.CommentID, comment.Content)
	}
	html += `</div>
			<h2>Credentials</h2>
			<form id="form">
				<input type="text" id="username" name="username" placeholder="Username" required>
				<input type="password" id="password" name="password" placeholder="Password" required>
				<button type="button" onclick="register()">Register</button>
			</form>
			<h2>Make a comment</h2>
			<form id="commentForm">
				<textarea id="content" name="content" placeholder="Content" required></textarea>
				<button type="button" onclick="postComment()">Post comment</button>
			</form>
			<h2>Remove a comment</h2>
			<form id="deleteForm">
				<input type="password" id="admin_password_box" name="admin_password_box" placeholder="Admin Password">
				<input type="number" id="comment_id" name="comment_id" placeholder="Comment ID" required>
				<button type="button" onclick="deleteComment()">Remove</button>
			</form>
		</div>
		<script>
			function register() {
				const formData = new FormData(document.getElementById('form'));
				postData('/register', new URLSearchParams(formData))
					.then(data => alert(data.message));
			}
			function postComment() {
				var username = document.getElementById('username').value;
				var password = document.getElementById('password').value;
				var content = document.getElementById('content').value;
				var data = { username: username, password: password, content: content };

				fetch('/comment', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify(data)
				})
				.then(response => response.json())
				.then(data => {
					alert(data.message);
					updateComments();  // Call updateComments regardless of success
				})
				.catch((error) => {
					console.error('Error:', error);
				});
			}

			function deleteComment() {
				var admin_password_box = document.getElementById('admin_password_box').value;
				var comment_id = parseInt(document.getElementById('comment_id').value);
				var username = document.getElementById('username').value;
				var password = document.getElementById('password').value;
				var data = { username: username, password: password, admin_password_box: admin_password_box, comment_id: comment_id };
			
				fetch('/delete', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
					},
					body: JSON.stringify(data)
				})
				.then(response => response.json())
				.then(data => {
					alert(data.message);
					updateComments();  // Call updateComments regardless of success
				})
				.catch((error) => {
					console.error('Error:', error);
				});
			}
			
			function postData(url = '', data = {}) {
				return fetch(url, {
				  method: 'POST', 
				  mode: 'cors',
				  cache: 'no-cache',
				  credentials: 'same-origin',
				  headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
				  },
				  redirect: 'follow',
				  referrerPolicy: 'no-referrer',
				  body: data
				}).then(response => response.json());
			  }

			function updateComments() {
				fetch('/updateComments')
				.then(response => response.json())
				.then(data => {
					let commentsHTML = "";
					data.forEach(comment => {
						commentsHTML += "<div class='comment'><b>" + comment.username + "</b> (" + new Date(comment.timestamp).toLocaleString() + ") [" + comment.comment_id + "]: " + comment.content + "</div>";
					});
					document.getElementById('comments').innerHTML = commentsHTML;
				})
				.catch((error) => {
					console.error('Error:', error);
				});
			}
		</script>
	</body>
	</html>`

	fmt.Fprint(w, html)
}

func getComments() ([]Comment, error) {
	rows, err := db.Query(`
		SELECT bbb.user_name, comments.comment_id, comments.content, comments.timestamp
		FROM comments
		JOIN bbb ON comments.sender_id = bbb.user_id
		ORDER BY comments.timestamp DESC
		LIMIT 20
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var comments []Comment
	for rows.Next() {
		var comment Comment
		if err := rows.Scan(&comment.Username, &comment.CommentID, &comment.Content, &comment.Timestamp); err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return comments, nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	userName := r.FormValue("username")
	password := r.FormValue("password")
	if userName == "" || password == "" {
		respondJSON(w, http.StatusBadRequest, "Username or password can't be empty, seriously?")
		return
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open the database: %v", err)
	}
	defer db.Close()

	var userExists int
	err = db.QueryRow("SELECT COUNT(*) FROM bbb WHERE user_name = $1", userName).Scan(&userExists)
	if err != nil || userExists > 0 {
		respondJSON(w, http.StatusBadRequest, "Username already taken, pick another")
		return
	}

	hash, err := HashPassword(password)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "Couldn't hash the password, whoops")
		return
	}

	_, err = db.Exec("INSERT INTO bbb (user_name, password_hash, admin) VALUES ($1, $2, $3)", userName, hash, false)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "Failed to insert user: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, "User "+userName+" registered, woohoo!")
}

func commentHandler(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Content  string `json:"content"`
	}

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, "Can't decode your input: "+err.Error())
		return
	}

	if p.Username == "" || p.Password == "" || p.Content == "" {
		respondJSON(w, http.StatusBadRequest, "Fill in all fields, please")
		return
	}

	var dbHash string
	err = db.QueryRow("SELECT password_hash FROM bbb WHERE user_name = $1", p.Username).Scan(&dbHash)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "User not found or other error")
		return
	}

	if !CheckPasswordHash(p.Password, dbHash) {
		respondJSON(w, http.StatusUnauthorized, "Wrong password, try again")
		return
	}

	var userID int
	err = db.QueryRow("SELECT user_id FROM bbb WHERE user_name = $1", p.Username).Scan(&userID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "Can't find your user ID, something's wrong")
		return
	}

	_, err = db.Exec("INSERT INTO comments (sender_id, content) VALUES ($1, $2)", userID, p.Content)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "Failed to insert comment: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, "Comment posted, good job.")
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		AdminPassword string `json:"admin_password_box"`
		CommentID     int    `json:"comment_id"`
	}

	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, "Can't decode your input: "+err.Error())
		return
	}

	if p.Username == "" || p.Password == "" || p.CommentID == 0 {
		respondJSON(w, http.StatusBadRequest, "Fill in all fields, please")
		return
	}

	var dbHash string
	var admin bool
	err = db.QueryRow("SELECT password_hash, admin FROM bbb WHERE user_name = $1", p.Username).Scan(&dbHash, &admin)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "User not found or other error")
		return
	}

	if !CheckPasswordHash(p.Password, dbHash) {
		respondJSON(w, http.StatusUnauthorized, "Wrong password, try again")
		return
	}

	if !admin && p.AdminPassword == adminPassword {
		_, err = db.Exec("UPDATE bbb SET admin = true WHERE user_name = $1", p.Username)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, "Couldn't promote you to admin: "+err.Error())
			return
		}
		admin = true
	}

	if !admin {
		respondJSON(w, http.StatusUnauthorized, "You need admin privileges for this action")
		return
	}

	var commentExists int
	err = db.QueryRow("SELECT COUNT(*) FROM comments WHERE comment_id = $1", p.CommentID).Scan(&commentExists)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "Failed to verify comment existence: "+err.Error())
		return
	}

	if commentExists == 0 {
		respondJSON(w, http.StatusBadRequest, "Comment does not exist")
		return
	}

	_, err = db.Exec("DELETE FROM comments WHERE comment_id = $1", p.CommentID)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, "Failed to delete comment: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, "Comment removed, whoop-dee-doo.")
}

func respondJSON(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
