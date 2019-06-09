from flask_perms.mixins import RoleMixinP, UserMixinP, PermissionMixinP
from flask_login import UserMixin
from testapp import db


class User(UserMixin, UserMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)

    def __repr__(self):
        return '<User %r>' % self.email


class Role(RoleMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)


class Permission(PermissionMixinP, db.Model):
    id = db.Column(db.Integer, primary_key=True)
