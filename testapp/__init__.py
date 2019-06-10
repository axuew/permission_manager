from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_perms import Flask_Perms
from .config import Config

app = Flask(__name__)
db = SQLAlchemy()
permissions = Flask_Perms()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    permissions.init_app(app)
    return app
