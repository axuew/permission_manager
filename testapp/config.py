from environs import Env
import os

env = Env()
env.read_env()


class Config:
    ENV = env.str('FLASK_ENV', 'production')
    DEBUG = ENV == 'development'
    SECRET_KEY = env.str("FLASK_SECRET_KEY", "placeholderTestingKey1234")
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    USER_PRIMARY_KEY = 'id'
    ROLE_PRIMARY_KEY = 'id'
