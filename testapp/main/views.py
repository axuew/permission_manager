from flask import current_app, request, session
from flask.views import MethodView

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
    return 'hello!'


@main.route('/num/<num>')
@permission_required(['test'], api=True)
def num_index(num):

    user = User.query.filter_by(id=num).first()

    return user.email


class CounterAPI(MethodView):

    @permission_required(['test'])
    def get(self):
        return "woot"

    def post(self):
        #session['counter'] = session.get('counter', 0) + 1
        return 'OK'


main.add_url_rule('/counter', view_func=CounterAPI.as_view('counter'))