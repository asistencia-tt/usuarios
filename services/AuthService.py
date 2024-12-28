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
