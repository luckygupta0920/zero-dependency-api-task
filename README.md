# Zero-Dependency API (Task 4)

This is a small web service built using **only Python's standard library** (`http.server`, `sqlite3`, `hashlib`, `secrets`, etc.). No external dependencies (like npm, pip, Flask, or FastAPI) were used.

## Core Features Implemented:
1. **Hand-written Router:** Handles GET and POST requests along with 404/405 error handling.
2. **Request Parsing:** Parses incoming JSON bodies safely.
3. **Authentication:** User registration and token-based login with SHA-256 password hashing.
4. **Persistence:** Uses Python's built-in `sqlite3` to store users and session tokens safely.
5. **Security & Rate Limiting:** Includes a basic IP-based rate limiter (max 5 requests per 10 seconds) and checks for oversized payloads (max 1MB).

## How to Run:
1. Clone the repository.
2. Run the server using the command:
   `python server.py`
3. The server will start on `http://localhost:8000` and automatically initialize the `database.db` file.
