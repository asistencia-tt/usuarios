from datetime import datetime
from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates
from models.user_roles import UserRoles

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
    role = db.Column(db.String(50), nullable=False, default=UserRoles.USUARIO)  # Roles: admin, tutor, docente, alumno, usuario
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

    @classmethod
    def validate_role(cls, role):
        """
        Valida que el rol proporcionado esté en los roles disponibles.
        """
        if role not in UserRoles.choices():
            raise ValueError(f"El rol '{role}' no es válido. Roles permitidos: {', '.join(UserRoles.choices())}.")

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

    @classmethod
    def update_user(cls, user_id, username=None, fullname=None, email=None, password=None, role=None, current_user=None):
        """
        Actualiza los detalles de un usuario, permitiendo cambiar el rol solo si el usuario es un admin.
        """
        user = cls.query.get(user_id)
        if not user:
            raise ValueError("El usuario no existe.")

        # Verificación de rol: solo admin puede actualizar el rol de otro usuario
        if role and current_user.role != UserRoles.ADMIN:
            raise ValueError("Solo los administradores pueden asignar roles.")

        # Validar el rol si se proporciona
        if role:
            cls.validate_role(role)
            user.role = role

        # Actualización de otros campos si se proporcionan
        if username:
            user.username = username
        if fullname:
            user.fullname = fullname
        if email:
            user.email = email
        if password:
            user.set_password(password)

        db.session.commit()
        return user
    
    def __repr__(self):
        """
        Representación en cadena del usuario (para depuración y registros).
        """
        return f"<User {self.username} - {self.role}>"
