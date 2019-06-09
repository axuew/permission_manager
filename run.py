from site import create_app, db
from site.models import User, Role, Permission

app = create_app()


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Permission=Permission)


if __name__ == '__main__':
    app.run()
