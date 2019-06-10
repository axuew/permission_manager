from testapp import create_app, db


app = create_app()

with app.app_context():
    from testapp.models import User, Role, Permission



@app.shell_context_processor
def make_shell_context():

    return dict(db=db, User=User, Role=Role, Permission=Permission)


if __name__ == '__main__':
    app.run()
