class UserRoles:
    ADMIN = 'admin'
    TUTOR = 'tutor'
    DOCENTE = 'docente'
    ALUMNO = 'alumno'
    USUARIO = 'usuario'

    @classmethod
    def choices(cls):
        return [cls.ADMIN, cls.TUTOR, cls.DOCENTE, cls.ALUMNO, cls.USUARIO]
