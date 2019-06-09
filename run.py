from testapp import create_app, db


app = create_app()


@app.shell_context_processor
def make_shell_context():

    return dict(db=db)


if __name__ == '__main__':
    app.run()
