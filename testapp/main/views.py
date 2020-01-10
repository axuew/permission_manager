from flask import current_app, request

from testapp import db, login_manager

from flask_perms.permission_control import permissionCheck, permission_required, bp_permission_required
from flask_perms import perm_manager as pm


from ..models import User

from . import main


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@main.route('/')
def index():
    pm.report()
    return 'hello!'


@main.route('/<num>')
@permission_required(['test'])
def num_index(num):

    user = User.query.filter_by(id=num).first()

    return user.email
