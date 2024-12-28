from flask import Flask
from config import config_dict
from extensions import db, migrate
from routes.auth import auth_bp
from routes.users import user_bp

def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(config_dict[config_name])
    
    db.init_app(app)
    migrate.init_app(app, db)

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/users')
    
    return app

if __name__ == '__main__':
    import os
    env = os.getenv('FLASK_ENV', 'development')
    app = create_app(env)
    app.run()
