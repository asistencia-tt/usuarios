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

def token_required(f):
    """
    Decorador para verificar el token JWT.
    """
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
    """
    Endpoint para registrar un nuevo usuario.
    """
    data = request.get_json()

    try:
        new_user = AuthService.register_user(
            username=data['username'],
            fullname=data.get('fullname', ""),  # Maneja fullname como opcional
            email=data['email'],
            password=data['password'],
        )
        return jsonify({
            "message": "Usuario creado con éxito",
            "user": new_user.to_dict()
        }), 201

    except CustomException as ex:
        return jsonify({"message": str(ex)}), 400

    except Exception as ex:
        return jsonify({"message": "An error occurred", "error": str(ex)}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Endpoint para autenticar usuarios.
    """
    data = request.get_json()

    authenticated_user = AuthService.login_user(email=data['email'], password=data['password'])

    if authenticated_user:
        token = jwt.encode(
            {
                'user_id': authenticated_user.id,
                'user_name': authenticated_user.username,
                'role': authenticated_user.role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
            },
            Config.JWT_SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"access_token": token}), 200
    return jsonify({"message": "Credenciales inválidas"}), 401


@auth_bp.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    """
    Endpoint protegido con JWT.
    """
    return jsonify({
        "message": f"Bienvenido, {current_user.username}!",
        "fullname": current_user.fullname,
        "email": current_user.email,
        "role": current_user.role
    })
