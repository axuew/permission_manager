# Flask Permission Manager

A permissions and access control system for Flask.  Allows granular permission-based access to routes, template elements, and general code.  Users can be assigned permissions directly, or assigned roles containing grouped permissions.  Other features include:

- Role inheritance (Roles can inherit permissions from other roles)
- Jinja macros for simple to complex permission-mediated changes to templates
- Database model mixins to add user, role, and permission functionality
- A shell accessible management system for access analysis
    - Permissioned/unpermissioned code, route, and template summary
    - User and role access reports, including permission source trees
    - Identification of unused and undeclared permissions 

Currently requires Flask-Login and SQLAlchemy.

## Basic Usage


#### App setup
```
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_perms import Flask_Perms

db = SQLAlchemy()
login_manager = LoginManager()
pm = Flask_Perms()

def create_app():
    app = Flask(__name__)
    db.init_app(app)
    login_manager.init_app(app)
    pm.init_app(app, db)
    return app
```

#### Model integration
Models need only include the proper mixins.  All association tables will be created automatically.
```
from flask_login import UserMixin
from yourapp import db, pm


class User(UserMixin, pm.UserMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)


class Role(pm.RoleMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)


class Permission(pm.PermissionMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)
```


#### Shell access and management initialization
```
from flask_perms import perm_manager


@app.shell_context_processor
def make_shell_context():
    return dict(pm=perm_manager)
```

#### Protecting a route
```
@app.route('/admin')
@permission_required(['admin_panel'])
def admin_page():

    return render_template('admin_panel.html", info)
```




