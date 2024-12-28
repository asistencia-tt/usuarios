from flask import Blueprint, request, jsonify
from extensions import db
from models import User
from services.AuthService import AuthService
import jwt
import datetime
from functools import wraps
from config import Config
from utils.errors.CustomException import CustomException


auth_bp = Blueprint('auth', __name__)

# Decorador para verificar el token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        
        try:
            token = token.split("Bearer ")[1]
            data = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    try:
        # Delegar la lógica de registro al servicio
        new_user = AuthService.register_user(
            username=data['username'],
            fullname=data['fullname'],
            email=data['email'],
            password=data['password']
        )
        return jsonify({
            "message": "User created successfully",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "fullname": new_user.fullname,
                "email": new_user.email
            }
        }), 201

    except CustomException as ex:
        return jsonify({"message": str(ex)}), 400

    except Exception as ex:
        return jsonify({"message": "An error occurred", "error": str(ex)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    authenticated_user = AuthService.login_user(email=data['email'], password=data['password'])

    if authenticated_user:
        token = jwt.encode(
            {
                'user_id': authenticated_user.id,
                'user_name': authenticated_user.username,
                'full_name': authenticated_user.fullname,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            },
            Config.JWT_SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"access_token": token}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@auth_bp.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({
        "message": f"Welcome, {current_user.username}!",
        "fullname": current_user.fullname,
        "email": current_user.email
    })
