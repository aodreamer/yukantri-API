# YUKANTRI

This is a simple Flask API for user registration, authentication, and queue management.

## Table of Contents

- [Features](#features)
- [Credentials](#credentials)
- [Endpoints](#endpoints)
- [CORS](#cors)
- [Authentication](#authentication)
- [Input Validation](#input-validation)
- [Rate Limiting](#rate-limiting)
- [Logging](#logging)
- [Swagger Documentation](#swagger-documentation)

## Features

- User registration and login
- JWT-based authentication
- Queue management
- Logging of user actions
- `Data Transfer Object` for Secure Transfer Process

## Credentials

The credentials for this project is stored in .env variable. I provide the .env.example so you can fill it by your own credentials

```bash
cp .env.example .env
```

```bash
nano .env
```

and fill it

### Enviroment Variable at Script

```python
from dotenv import load_dotenv
import os

app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY_JWT')
```

## Endpoints

- /api/register (POST): User registration
- /api/login (POST): User login
- /api/logout (POST): User logout
- /api/refresh (POST): Refresh access token
- /api/get_queue_number (POST): Get a queue number
- /api/view_log (GET): Get log data

## CORS

using CORS from `flask_cors` package

```python
from flask_cors import CORS
CORS(app)
```

## Authentication

- The /api/register endpoint requires a JSON payload with username, email, and password.
- The /api/login endpoint requires a JSON payload with username and password.
- The /api/logout endpoint requires a valid 'JWT' in the Authorization header.
- The /api/refresh endpoint refreshes the 'JWT' access token and requires a valid refresh token.
- The /api/get_queue_number endpoint require a valid 'JWT' in the Authorization header.

## Input Validation

Input validation is used to validate email and password that inputed by user. Email validation using `email_validator` packcage

```python
from email_validator import validate_email, EmailNotValidError
#somecode
@app.route('/api/register', methods=['POST'])
def register():
    #somecode
    # Validasi email menggunakan email_validator
    try:
        v = validate_email(email)
        email = v["email"]
    except EmailNotValidError as e:
        return jsonify(message=f'Invalid email: {str(e)}'), 400

    # Tambahkan aturan validasi password
    if len(password) < 8:
        return jsonify(message='Password must be at least 8 characters long'), 400
```

## Rate Limiting

The /api/get_queue_number endpoint is rate-limited to 10 requests per minute per user.

```python
from flask_limiter import Limiter
limiter = Limiter(get_remote_address, app=app,
    storage_uri="memory://",
)

#some code
class QueueResource(Resource):
    """
    Resource for handling queue operations.
    """
    @limiter.limit("10 per minute")
```

## Logging

All user actions are logged to the `app.log` file in the project root. logging system using `logging` package

- The `/api/view_log` endpoint will return the content of `app.log`

```python
import logging
logging.basicConfig(filename='app.log')

@app.route('/api/login', methods=['POST'])
def login():
    #somecode
    if user and user.check_password(password):
        #somecode
        logging.info(f"User {username} logged in successfully")
```

## Swagger Documentation

Swagger documentation is available at http://<your-ip>:<your-port>/apidocs. You can use the Swagger UI to interact with the API and try out different endpoints. The integration of Swagger using `flasgger` package

```python
from flasgger import Swagger
#somecode

@app.route('/api/register', methods=['POST'])
def register():
    """
    Register a new user.

    ---
    consumes:
      - application/json
    parameters:
      - name: user
        in: body
        required: true
        schema:
          id: User
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              description: The username of the user.
            email:
              type: string
              format: email
              description: The email address of the user.
            password:
              type: string
              description: The password of the user.
    responses:
      201:
        description: User registered successfully
      400:
        description: Bad Request - Invalid input
    produces:
      - application/json
    """
```
