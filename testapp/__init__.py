from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_perms import Flask_Perms
from .config import Config
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()
pm = Flask_Perms()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    login_manager.init_app(app)
    pm.init_app(app, db)
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
