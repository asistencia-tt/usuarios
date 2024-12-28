from extensions import db

from models import User
from utils.errors.CustomException import CustomException

class AuthService:

    @classmethod
    def login_user(cls, email, password):
        """
        Verifica la identidad del usuario llamando al procedimiento almacenado.
        """
        try:
            authenticated_user = None
            result = db.session.query(User).filter_by(email=email).first()
            
            if result is not None and result.check_password(password):
                return result  # Usuario autenticado correctamente
            return None  # Usuario no autenticado
        
        except Exception as ex:
            raise CustomException(f"Error al autenticar usuario: {ex}")

    @classmethod
    def register_user(cls, username, fullname, email, password):
        """
        Crea un nuevo usuario y lo guarda en la base de datos.
        """
        try:
            # Verificar si el email ya está registrado
            existing_user = db.session.query(User).filter_by(email=email).first()
            if existing_user:
                raise CustomException("Email already registered")

            # Crear el nuevo usuario
            user = User(username=username, fullname=fullname, email=email)
            user.set_password(password)

            # Guardar en la base de datos
            db.session.add(user)
            db.session.commit()
            return user

        except Exception as ex:
            raise CustomException(f"Error al registrar usuario: {ex}")