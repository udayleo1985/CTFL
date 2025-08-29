# Secure API with JWT Authentication

## Overview

This project provides a secure API built using FastAPI that implements user registration, login, and profile retrieval with JWT-based authentication. Passwords are hashed securely, JWTs are signed with HS256, and token expiration and validation are enforced.

## Features

- **POST /register**: Register a new user with email and password (passwords hashed using bcrypt).
- **POST /login**: Authenticate user and issue a JWT access token (HS256) with expiration.
- **GET /profile**: Protected route requiring a valid JWT access token.
- Comprehensive input validation and error handling.
- Secure password management and authentication.

## Requirements

- Python 3.7+
- FastAPI
- Uvicorn
- Passlib (bcrypt)
- PyJWT
- Email-validator

## Installation

pip install fastapi uvicorn passlib[bcrypt] pyjwt email-validator
## Running the API Server

uvicorn secure_api:app –reload

This starts the API server on `http://127.0.0.1:8000`.

## API Endpoints

### 1. Register a User

POST /register
Content-Type: application/json

{
"email": "user@example.com",
"password": "your_secure_password"
}

- Registers a new user with a hashed password.
- Returns 201 on success, 400 if email already registered.

### 2. Login and Get JWT Access Token

POST /login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=your_secure_password

text

- Returns a JSON with the access token and token type:

{
"access_token": "eyJhbGciOiJI...",
"token_type": "bearer"
}

- Returns 401 if username or password is incorrect.

### 3. Access Protected Profile Route

GET /profile
Authorization: Bearer <access_token>

- Requires a valid JWT access token in the Authorization header.
- Returns user's email and a welcome message.
- Returns 401 if the token is missing, invalid, or expired.

## Testing with curl

Register a new user:

curl -X POST "http://127.0.0.1:8000/register"
-H "Content-Type: application/json"
-d '{"email":"test@example.com","password":"testpass"}'


Login to get the token:

curl -X POST "http://127.0.0.1:8000/login"
-F "username=test@example.com"
-F "password=testpass"

Access protected profile route:

curl -H "Authorization: Bearer <access_token>" http://127.0.0.1:8000/profile

Replace `<access_token>` with the token received from login.

## Security Notes

- Passwords are hashed securely using bcrypt.
- JWT tokens are signed with HS256 and expire after 30 minutes.
- Only authenticated users with valid tokens can access protected routes.
- Input validations are done via Pydantic and OAuth2 standards.

## Disclaimer

This project is intended for educational purposes. In production, consider:
- Using HTTPS for all client-server communication.
- Storing secrets securely in environment variables or vaults.
- Implementing refresh tokens and token revocation.
- Using database persistence rather than in-memory storage.
