from flask import current_app, request

from testapp import db
from ..models import User

from . import main


@main.route('/<num>')
def index(num):

    user = User.query.filter_by(id=num).first()

    return user.email
