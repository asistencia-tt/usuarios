from extensions import db
from models import User
from utils.errors.CustomException import CustomException


class AuthService:
    """
    Servicio para manejar la lógica de autenticación y registro de usuarios.
    """

    @classmethod
    def login_user(cls, email, password):
        """
        Verifica la identidad del usuario.
        """
        try:
            user = User.query.filter_by(email=email, is_active=True).first()
            if user and user.check_password(password):
                return user
            return None
        except Exception as ex:
            raise CustomException(f"Error al autenticar usuario: {ex}")

    @classmethod
    def register_user(cls, username, fullname, email, password):
        """
        Crea un nuevo usuario y lo guarda en la base de datos.
        """
        try:
            # Verificar si el email ya está registrado
            if User.query.filter_by(email=email).first():
                raise CustomException("El email ya está registrado.")

            # Verificar si el username ya está registrado
            if User.query.filter_by(username=username).first():
                raise CustomException("El nombre de usuario ya está registrado.")

            #  Establecer un valor predeterminado para fullname si no se proporciona
            fullname = fullname or ""

            # Crear el nuevo usuario
            user = User(username=username, fullname=fullname, email=email, role="usuario")
            user.set_password(password)

            # Guardar en la base de datos
            db.session.add(user)
            db.session.commit()
            return user

        except Exception as ex:
            raise CustomException(f"Error al registrar usuario: {ex}")
