from flask import current_app, request

from testapp import db


from . import main


@main.route('/<num>')
def index(num):
    from ..models import User
    user = User.query.filter_by(id=num).first()

    return user.email
