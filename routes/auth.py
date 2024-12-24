from flask import Blueprint, request, jsonify
from extensions import db
from models import User
import jwt
import datetime
from functools import wraps
from config import Config

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
    user = User(
        username=data['username'],
        fullname=data['fullname'],
        email=data['email']
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        token = jwt.encode(
            {
                'user_id': user.id,
                'user_name': user.username,
                'full_name': user.fullname,
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
