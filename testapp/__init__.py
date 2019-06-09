from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_perms import Flask_Perms
from .config import Config

app = Flask(__name__)
db = SQLAlchemy()



def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)

    with app.app_context():
        permissions = Flask_Perms()
        permissions.init_app(app)
    return app
