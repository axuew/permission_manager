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
First, we need to initialize the extension with the app.  The permission manager requires a database instance for initialization, so be sure to instantiate/initialize it first.
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
Database models need only to include the appropriate mixin.  All association tables will be created automatically.  Add the UserMixinP mixin to your model representing users.  Be sure to also inherit the Flask Login UserMixin.  The role and permission mixins can be integrated into other models or just left as the minimum definition below: 
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

#### Configuration Values
To function, the permission manager needs the names of your user, role, and permission models, as well as the primary key names for each.  Additionally, if you'd like to set a different name for the administrator/root role, set ROOT_ROLE.  All current config keys and default values are below:

- USER_MODEL_NAME: "User"
- ROLE_MODEL_NAME: "Role"
- PERMISSION_MODEL_NAME: "Permission"
- USER_PRIMARY_KEY: "id"
- ROLE_PRIMARY_KEY: "id"
- PERMISSION_PRIMARY_KEY: "id"
- ROOT_ROLE: "Head Admin"

#### Shell access and management initialization
Permissions, roles, and assignments to users can be managed and analyzed from the Flask shell context. Add the perm_manager to a shell context processor. 
```
from flask_perms import perm_manager


@app.shell_context_processor
def make_shell_context():
    return dict(pm=perm_manager)
```

#### Protecting a route
Routes are protected using the permission_required decorator and supplying a list of required permission names, a list of required role names (or role objects), or both.  For example, if we want to limit access to the administrator page, we could do it using a single permission 'admin_panel' as below:
```
from flask_perms.permission_control import permission_required

@app.route('/admin')
@permission_required(['admin_panel'])
def admin_page():

    return render_template('admin_panel.html", info)
```

If we wanted to limit access to a certain API endpoint to accounting staff that also have the 'get_summary' permission:
```
@app.route('/accounting/summary')
@permission_required(permissions=['get_summary'], roles=['Accounting'], api=True)
def get_summary_info():
``` 

#### Creating Permissions
Permissions at their core exist as a name and a description.  The name attribute is also the string used to specify a required permission.
```
NewPermission = Permission(name='admin_panel', description='Grants access to the administration page.')
db.session.add(NewPermission)
db.session.commit()
```



#### Assigning Permissions and Roles
To assign a permission, simply call ```addPermission``` on the user or role instance.  Similarly, use ```addRole``` to assign a role to a user.  Roles and permission can be assigned using their respective names, the objects themselves, or their primary key value.
```
bob = User.query.filter_by(name='Bob').first()

# Option1
bob.addPermission(NewPermission)

# Option2
bob.addPermission(permName='admin_panel')

# Option3
bob.addPermission(permId=1)
```

Roles can also inherit permissions from other roles.  If a role inherits from multiple roles, it gains all their permissions.
```
basicUser = Role.query.filter_by(name='Basic User').first()
accounting = Role.query.filter_by(name='Accounting').first()

accounting.inheritRole(basicUser)
accounting.addPermission(permName='get_summary')
```

#### Analyzing Access
From the shell context, a report can be generated detailing permissioned/unpermissioned code, routes, and templates, unused and undeclared permissions, and permissioned users.  Individual User or Role reports are also available, which detail permissions, permissions sources and role inheritance trees, as well as show a summary of template and template element access.  

```
# To generate the permission summary report
pm.report()

# To generate an individual user report
# Takes the primary key of the user (shown in the permission summary report)
pm.userSummary(id=1)

# To generate an individual user report
pm.roleSummary(id=1)
```

#### Instantiating the Permissions Database and Creating the Root Role
Permission database instances can be created for any missing app utilized permission simply by calling ```populate_from_app``` on your permission manager instance.  The root role contains all defined permissions- useful for debugging and for ensuring head administrators have full access.  This role can be created and maintained automatically by calling ```create_root``` on your permission manager instance.  These actions can be done simultaneously by calling ```init_permissions```.  Support planned for exporting and importing permission and role definitions.


#### Reserved Permissions
The permissions ```view_missing_permissions``` and ```view_permission_errors``` are generated automatically, and are used for controlling debug feedback access during a permission check.  The former will grant the user feedback on what missing permission(s) were required on a route or api call, and the later will grant access to notifications of misconfigured permission checks during usage.

