import os
import sys

from flask import url_for, Blueprint, current_app, _app_ctx_stack, has_app_context
from werkzeug.local import LocalProxy

from . import filters
from .settings import ROOT_ROLE, IGNORE_EMPTY, STORE_TYPE, USER_SCHEMA, defaultPermissions

from .mixins.mixins import _createUserMixin, _createRoleMixin, _createPermissionMixin
from .mixins.models import _createRoleLinkModel, _createCrossLinkModels

from .manager import _createManager


class Flask_Perms(object):
    """
    Used for permission control integration in one or more Flask applications.  Initialize with a SQLAlchemy database
    instance.

    """
    def __init__(self, app=None, db=None, **kwargs):
        for k, v in kwargs.items():
            if app and k == 'db':
                db = v
            setattr(self, k, v)
        if app:
            self.init_app(app, db)

    def init_app(self, app, db):

        app.config.setdefault('STORE_TYPE', STORE_TYPE)
        self.store_type = app.config['STORE_TYPE']

        app.config.setdefault('USER_MODEL_NAME', 'User')
        app.config.setdefault('ROLE_MODEL_NAME', 'Role')
        app.config.setdefault('PERMISSION_MODEL_NAME', 'Permission')
        self.user_model = app.config['USER_MODEL_NAME']
        self.role_model = app.config['ROLE_MODEL_NAME']
        self.perm_model = app.config['PERMISSION_MODEL_NAME']

        app.config.setdefault('USER_TABLE_NAME', 'users')
        app.config.setdefault('ROLE_TABLE_NAME', 'roles')
        app.config.setdefault('PERMISSION_TABLE_NAME', 'permissions')
        self.user_table = app.config['USER_TABLE_NAME']
        self.role_table = app.config['ROLE_TABLE_NAME']
        self.perm_table = app.config['PERMISSION_TABLE_NAME']

        app.config.setdefault('USER_PRIMARY_KEY', 'id')
        app.config.setdefault('ROLE_PRIMARY_KEY', 'id')
        app.config.setdefault('PERMISSION_PRIMARY_KEY', 'id')
        self.user_pk = app.config['USER_PRIMARY_KEY']
        self.role_pk = app.config['ROLE_PRIMARY_KEY']
        self.perm_pk = app.config['PERMISSION_PRIMARY_KEY']

        app.config.setdefault('ROLE_LINK_NAME', 'role_links')
        app.config.setdefault('USER_ROLE_LINK_NAME', 'user_role_links')
        app.config.setdefault('USER_PERMISSION_LINK_NAME', 'user_permission_links')
        app.config.setdefault('ROLE_PERMISSION_LINK_NAME', 'role_permission_links')
        self.role_link = app.config['ROLE_LINK_NAME']
        self.user_role_link = app.config['USER_ROLE_LINK_NAME']
        self.user_perm_link = app.config['USER_PERMISSION_LINK_NAME']
        self.role_perm_link = app.config['ROLE_PERMISSION_LINK_NAME']

        app.config.setdefault('USER_SCHEMA', USER_SCHEMA)
        app.config.setdefault('ROOT_ROLE', ROOT_ROLE)
        app.config.setdefault('IGNORE_EMPTY', IGNORE_EMPTY)
        self.user_schema = app.config['USER_SCHEMA']
        self.root_role = app.config['ROOT_ROLE']
        self.ignore_empty = app.config['IGNORE_EMPTY']

        app.add_template_filter(filters.perm_check)
        app.add_template_filter(filters.is_subset)
        blueprint = Blueprint('permission', __name__, template_folder='templates')
        app.register_blueprint(blueprint)

        self.table_dict = {'user': app.config['USER_TABLE_NAME'],
                           'role': app.config['ROLE_TABLE_NAME'],
                           'perm': app.config['PERMISSION_TABLE_NAME']
                           }

        self.RoleLink = _createRoleLinkModel(self, db)

        self.UserMixinP = _createUserMixin(self, db)

        self.RoleMixinP = _createRoleMixin(self, db)

        self.PermissionMixinP = _createPermissionMixin(self, db)

        self.UserPermissionLink, \
        self.RolePermissionLink, \
        self.UserRoleLink = _createCrossLinkModels(self, db)

        self.root_path = app.root_path
        self.app_db = db

        app.extensions['flask_perms'] = self

    def _get_db(self):
        """
        Returns the application database instance.
        :return: SQLAlchemy database instance
        """
        return current_app.extensions['sqlalchemy'].db

    def _get_model(self, model):
        """
        Returns the requested permissions-related database model instance for the application.
        :param model: (str, options= 'user', 'role', 'perm') The model to return.
        :return: SQLAlchemy Model instance
        """
        for c in self.app_db.Model._decl_class_registry.values():
            if hasattr(c, '__table__') and c.__tablename__ == self.table_dict[model]:
                return c

    def _update_app_context_with_perm_manager(self):
        """
        Adds an initialized permissions manager object to the application context stack.
        :return: None
        """
        ctx = _app_ctx_stack.top
        pm = _createManager(self, current_app, self._get_db())()
        pm.init()
        ctx.perm_manager = pm


# Importable instance of the Permission_manager
perm_manager = LocalProxy(lambda: _get_manager())


def _get_manager():
    """
    Retrieve the permission manager attached to the application context stack.
    :return: Permission manager instance (or None)
    """
    if has_app_context() and not hasattr(_app_ctx_stack.top, 'perm_manager'):
        current_app.extensions['flask_perms']._update_app_context_with_perm_manager()

    return getattr(_app_ctx_stack.top, 'perm_manager', None)
