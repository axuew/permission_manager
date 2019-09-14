from flask import current_app, request

from testapp import db

from flask_perms.permission_control import permissionCheck, permission_required, bp_permission_required

from ..models import User

from . import main


@main.route('/')
def index():

    return "Index!"


@main.route('/<num>')
@permission_required(['test'])
def num_index(num):

    user = User.query.filter_by(id=num).first()

    return user.email
