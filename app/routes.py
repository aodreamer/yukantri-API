from flask import request, jsonify, make_response, abort, Response, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, jwt_required, create_refresh_token, verify_jwt_in_request, get_jwt, set_access_cookies

from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from app.models import User, QueueItem, RevokedToken

from datetime import datetime
from datetime import timedelta
from datetime import timezone

from dotenv import load_dotenv
import os

import logging

from flask_cors import CORS, cross_origin
from flask_restful import Resource, Api

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flasgger import Swagger

from email_validator import validate_email, EmailNotValidError

logging.basicConfig(filename='app.log')
api = Api(app)
CORS(app)
Swagger(app)

limiter = Limiter(get_remote_address, app=app,
    storage_uri="memory://",
)

app.config['JWT_SECRET_KEY'] = os.getenv('SECRET_KEY_JWT')
jwt = JWTManager(app)

# Fungsi checker untuk memeriksa apakah access_token direvoke
def check_revoked_tokens():
    current_path = request.path

    # Mengecualikan endpoint /api/refresh dari pengecekan
    if current_path == '/api/refresh':
        return

    verify_jwt_in_request(optional=True)

    jwt_type = get_jwt()['type'] if 'type' in get_jwt() else None
    if jwt_type == 'access':
        jti = get_jwt()['jti'] if 'jti' in get_jwt() else None
        if jti:
            revoked_token = RevokedToken.query.filter_by(jti=jti).first()
            if revoked_token:
                abort(401, 'Access token has been revoked')

# Middleware untuk memeriksa setiap permintaan
@app.before_request
def before_request():
    check_revoked_tokens()


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

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Validasi email menggunakan email_validator
    try:
        v = validate_email(email)
        email = v["email"]
    except EmailNotValidError as e:
        return jsonify(message=f'Invalid email: {str(e)}'), 400

    # Tambahkan aturan validasi password
    if len(password) < 8:
        return jsonify(message='Password must be at least 8 characters long'), 400

    # Hash password sebelum disimpan ke dalam database
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(message='User registered successfully'), 201

@app.route('/api/login', methods=['POST'])
def login():
    """
    Log in a user.

    ---
    consumes:
      - application/json
    parameters:
      - in: body
        name: user
        required: true
        schema:
          id: UserLogin
          required:
            - username
            - password
          properties:
            username:
              type: string
              description: The username of the user.
            password:
              type: string
              description: The password of the user.
    responses:
      200:
        description: Login successful! You got your JWT. See it in cookies.
      401:
        description: Invalid username or password
    produces:
      - application/json
    """
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')


    # Tambahkan aturan validasi password sesuai kebutuhan
    if len(password) < 8:
        return jsonify(message='Password must be at least 8 characters long'), 400

    # Temukan pengguna berdasarkan nama pengguna
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        response = make_response(jsonify(message='Login successful! you got your JWT. See it in cookies'))
        response.set_cookie('access_token', value=access_token, httponly=True)
        response.set_cookie('refresh_token', value=refresh_token, httponly=True)

        logging.info(f"User {username} logged in successfully")

        return response, 200
    else:
        logging.warning(f"Failed login attempt for inputed user {username}")
        return jsonify(message='Invalid username or password'), 401


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout the current user.

    ---
    consumes:
      - application/json
    responses:
      200:
        description: Logout successful
      401:
        description: Invalid or missing JWT token
    produces:
      - application/json
    """
    jti = get_jwt()['jti'] if 'jti' in get_jwt() else None
    revoked_token = RevokedToken(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()
    response = make_response(jsonify(message='Logout successful'))
    response.set_cookie('access_token', expires=0)  # Set expiry ke masa lalu untuk menghapus cookie

    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    logging.info(f"User {user.username} logged out successfully")
    return response, 200


@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Refresh the JWT token.

    ---
    consumes:
      - application/json
    produces:
      - application/json
    responses:
      200:
        description: Refresh Token successful
      401:
        description: Invalid or missing refresh token
    """
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity)
    response = make_response(jsonify(message='Refresh Token successful! you got your JWT. See it in cookies'))
    response.set_cookie('access_token', value=access_token, httponly=True)
    return response, 200

# Kelas DTO untuk pengguna
class UserDTO:
    def __init__(self, user):
        self.id = user["id"]
        self.username = user["username"]

# Kelas DTO untuk antrean
class QueueItemDTO:
    def __init__(self, queue_item):
        self.user = UserDTO(queue_item.user.__dict__)
        print(type(self.user))
        self.queue_number = queue_item.queue_number



# Resource untuk User API
class UserResource(Resource):
    def get(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if user:
            user_dto = UserDTO(user.__dict__)
            return {"user": vars(user_dto)}, 200
        else:
            return {"message": "User not found"}, 404

# Resource untuk Antrean API
class QueueResource(Resource):
    """
    Resource for handling queue operations.
    """
    @limiter.limit("10 per minute")
    @jwt_required()
    def post(self):
        """
        Add a user to the queue.

        ---
        consumes:
          - application/json
        produces:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              id: Queue
              type: object
              properties:
                username:
                  type: string
            example:
              username: john_doe
        responses:
          201:
            description: User added to the queue successfully
            schema:
              type: object
              properties:
                message:
                  type: string
                queue_item:
                  type: object
                  properties:
                    username:
                      type: string
                    queue_number:
                      type: integer
          401:
            description: Unauthorized, user not logged in
        """
        current_user_id = get_jwt_identity()
        user = User.query.filter_by(id=current_user_id).first()

        if not user:
            return jsonify(message='Login first!'), 401

        # Buat objek pengantrian baru
        new_queue_item = QueueItem(user=user, queue_number=get_next_queue_number(), entry_time=datetime.utcnow())

        # Tambahkan objek ke dalam database
        db.session.add(new_queue_item)
        db.session.commit()

        # Log ke file log
        logging.info(f"User {user.username} added to queue successfully")

        # Kembalikan DTO sebagai respons API
        queue_item_dto = QueueItemDTO(new_queue_item)
        queue_item_dto_dict = {
            'username' : queue_item_dto.user.username,
            'queue_number': queue_item_dto.queue_number,    }
        return {"message": 'User added successfully', "queue_item": queue_item_dto_dict}, 201


def get_next_queue_number():
    last_queue_item = QueueItem.query.order_by(QueueItem.id.desc()).first()
    return last_queue_item.queue_number + 1 if last_queue_item else 1

@app.route('/api/view_log', methods=['GET'])
def view_log():
    """
        View application logs.

        ---
        produces:
          - text/plain
        responses:
          200:
            description: Log content
            schema:
              type: string
          500:
            description: Internal Server Error
        """
    try:
        with open('app.log', 'r') as log_file:
            log_content = log_file.read()
        return Response(log_content, mimetype='text/plain', status=200)
    except Exception as e:
        return jsonify(message=f"Error viewing log: {str(e)}"), 500


api.add_resource(UserResource, '/user/<int:user_id>')
api.add_resource(QueueResource, '/api/get_queue_number')