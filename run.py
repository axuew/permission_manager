from testapp import create_app, db

app = create_app()

from testapp.models import User, Role, Permission
from flask_perms import perm_manager


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Permission=Permission, pm=perm_manager)


if __name__ == '__main__':
    app.run()
