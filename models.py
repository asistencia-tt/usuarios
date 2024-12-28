from datetime import datetime
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates


class User(db.Model):
    """
    Modelo de usuario que representa los datos de autenticación y perfil.
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    fullname = db.Column(db.String(120), nullable=True)  # Ahora es opcional
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='usuario')  # Roles: admin, tutor, docente, alumno, usuario
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, username, email, role='usuario', fullname=None):
        """
        Constructor del modelo de usuario.
        """
        self.username = username
        self.email = email
        self.role = role
        self.fullname = fullname

    def set_password(self, password):
        """
        Genera un hash para la contraseña proporcionada y la almacena.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Verifica si la contraseña proporcionada coincide con el hash almacenado.
        """
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        """
        Convierte el modelo en un diccionario para facilitar la serialización.
        """
        return {
            "id": self.id,
            "username": self.username,
            "fullname": self.fullname,  # Puede ser `None` si no se proporciona
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

    @validates('email')
    def validate_email(self, key, value):
        """
        Valida que el email tenga un formato correcto.
        """
        if "@" not in value or "." not in value:
            raise ValueError("El email no tiene un formato válido.")
        return value.lower()

    @validates('username')
    def validate_username(self, key, value):
        """
        Valida que el username tenga al menos 4 caracteres.
        """
        if len(value) < 4:
            raise ValueError("El nombre de usuario debe tener al menos 4 caracteres.")
        return value

    def __repr__(self):
        """
        Representación en cadena del usuario (para depuración y registros).
        """
        return f"<User {self.username} - {self.role}>"
