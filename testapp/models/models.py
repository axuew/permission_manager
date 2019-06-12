from flask_login import UserMixin
from testapp import db, pm


class User(UserMixin, pm.UserMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)

    def __repr__(self):
        return '<User %r>' % self.email


class Role(pm.RoleMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)


class Permission(pm.PermissionMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)
