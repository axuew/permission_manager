from flask import current_app, request
from flask_login import login_user, logout_user, current_user

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
    return 'Hello!'


@main.route('/login/<id>')
def login(id):
    user = User.query.filter_by(id=id).first()
    login_user(user, remember=True)
    return f'Logged in {user.email}'


@main.route('/logout')
def logout():
    logout_user()
    return f'Logged out'


@main.route('/num/<num>')
@permission_required(['test'], roles=['Test Role'], api=True)
def num_index(num):

    user = User.query.filter_by(id=num).first()

    return user.email

