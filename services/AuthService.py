from extensions import db
from models.user import User
from utils.errors.CustomException import CustomException, ValidationError

class AuthService:
    @classmethod
    def login_user(cls, email, password):
        try:
            user = User.query.filter_by(email=email, is_active=True).first()
            if user and user.check_password(password):
                return user
            raise ValidationError("Credenciales inválidas")
        except Exception as ex:
            raise CustomException(f"Error al autenticar usuario: {ex}")

    @classmethod
    def register_user(cls, username, fullname, email, password):
        try:
            if User.query.filter_by(email=email).first():
                raise ValidationError("El email ya está registrado.")
            if User.query.filter_by(username=username).first():
                raise ValidationError("El nombre de usuario ya está registrado.")

            fullname = fullname or ""
            user = User(username=username, fullname=fullname, email=email, role="usuario")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return user

        except CustomException as custom_ex:
            raise custom_ex
        except Exception as ex:
            raise CustomException(f"Error al registrar usuario: {ex}")
