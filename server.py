import http.server
import socketserver
import json
import sqlite3
import hashlib
import secrets
import time

PORT = 8000

# Dictionary to store IP request timestamps for rate limiting
rate_limit_data = {}
RATE_LIMIT_WINDOW = 10  # Seconds
MAX_REQUESTS = 5        # Max requests per window

# Initialize Database and Tables
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT)''')
    conn.commit()
    conn.close()

# Password Hash Function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Route Handler
class RequestHandler(http.server.SimpleHTTPRequestHandler):
    
    # Helper function to send HTTP responses
    def _send_response(self, status, payload):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    # Basic Rate Limiter
    def is_rate_limited(self):
        client_ip = self.client_address[0]
        current_time = time.time()
        
        if client_ip not in rate_limit_data:
            rate_limit_data[client_ip] = []
            
        # Remove old requests outside the time window
        rate_limit_data[client_ip] = [t for t in rate_limit_data[client_ip] if current_time - t < RATE_LIMIT_WINDOW]
        
        if len(rate_limit_data[client_ip]) >= MAX_REQUESTS:
            return True
            
        rate_limit_data[client_ip].append(current_time)
        return False

    # Check session token
    def get_user_from_token(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        token = auth_header.split(" ")[1]
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT username FROM sessions WHERE token=?", (token,))
        result = c.fetchone()
        conn.close()
        
        return result[0] if result else None

    # Handle GET requests
    def do_GET(self):
        if self.is_rate_limited():
            self._send_response(429, {"error": "Too many requests. Please slow down."})
            return

        if self.path == '/':
            self._send_response(200, {"message": "Server is running perfectly!"})
            
        # Protected Route: Requires Token
        elif self.path == '/profile':
            username = self.get_user_from_token()
            if username:
                self._send_response(200, {"message": f"Welcome to your profile, {username}!", "secret_data": "This is protected data."})
            else:
                self._send_response(401, {"error": "Unauthorized. Please provide a valid token."})
        else:
            self._send_response(404, {"error": "Path not found"})

    # Handle POST requests
    def do_POST(self):
        if self.is_rate_limited():
            self._send_response(429, {"error": "Too many requests. Please slow down."})
            return

        # Security: Prevent oversized bodies (max 1MB)
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 1024 * 1024:
            self._send_response(413, {"error": "Payload too large"})
            return

        if self.path in ['/register', '/login']:
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                username = data.get('username')
                password = data.get('password')

                if not username or not password:
                    self._send_response(400, {"error": "Username and password required"})
                    return

                hashed_pw = hash_password(password)
                conn = sqlite3.connect('database.db')
                c = conn.cursor()
                
                if self.path == '/register':
                    try:
                        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
                        conn.commit()
                        self._send_response(201, {"message": "User registered successfully!"})
                    except sqlite3.IntegrityError:
                        self._send_response(400, {"error": "Username already exists"})
                        
                elif self.path == '/login':
                    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_pw))
                    if c.fetchone():
                        token = secrets.token_hex(16)
                        c.execute("INSERT INTO sessions (token, username) VALUES (?, ?)", (token, username))
                        conn.commit()
                        self._send_response(200, {"message": "Login successful!", "token": token})
                    else:
                        self._send_response(401, {"error": "Invalid username or password"})
                conn.close()
            except json.JSONDecodeError:
                self._send_response(400, {"error": "Invalid JSON format"})
        else:
            self._send_response(404, {"error": "Path not found"})

if __name__ == "__main__":
    init_db()
    with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
        print(f"Server starting on port {PORT}...")
        httpd.serve_forever()