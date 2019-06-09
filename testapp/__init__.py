from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from .config import Config

app = Flask(__name__)
db = SQLAlchemy()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    with app.app_context():
        pass
    return app
