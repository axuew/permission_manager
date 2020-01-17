from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.exc import InvalidRequestError


def _modelActionBase(self, instance=None, instanceName=None, kvDict=None, **kwargs):
    """
    Grants a role to the user from which permissions will be inherited.  Priority to arguments goes role,
    roleName, then roleId.

    :param role: (Role) A role instance
    :param roleName: (str) A role instance name
    :param roleId: A role primary key value.
    :return: A tuple containing a boolean representing the success of the operation, and a response string.
    """

    model = kwargs['model']
    db = kwargs['db']
    action = kwargs['action']
    modelType = kwargs['modelType']

    responseDict = {'role': {'removed': f"NOTE it may still inherit the role "
                                        f"(or the role's permissions) through another inherited role's inherited roles."
                             },
                    'permission': {'removed': 'NOTE it may still be present in a given role.'}
                    }

    if instance:
        try:
            activeInstance = instance
        except AttributeError:
            return False, f'{instance} is not a valid {modelType}.'

    elif instanceName:
        activeInstance = model.query.filter_by(name=instanceName).first()
        if not activeInstance:
            return False, f'{model} is not a valid {modelType} name.'

    elif kvDict:
        try:
            activeInstance = model.query.filter_by(**kvDict).all()
        except InvalidRequestError:
            db.session.rollback()
            return False, f"Invalid {modelType} property given."
        if not activeInstance:
            return False, f'No existing {modelType} found matching values.'
        if len(activeInstance) > 1:
            return False, f'{len(activeInstance)} {modelType} found matching given values.'
        activeInstance = activeInstance[0]

    else:
        return False, f'One of arguments {modelType}, {modelType}Name, or kvDict must be specified.'

    if action == 'add':
        if (modelType == 'role' and activeInstance in self.roles) or \
                (modelType == 'permission' and activeInstance in self.permissions):
            return False, f"{self} already has {activeInstance}."

    if action == 'remove':
        if (modelType == 'role' and activeInstance not in self.roles) or \
                (modelType == 'permission' and activeInstance not in self.permissions):
            return False, f"{self} does not directly have {activeInstance}."

    if action == 'add':
        if modelType == 'role':
            self.roles.append(activeInstance)
        elif modelType == 'permission':
            self.permissions.append(activeInstance)
    elif action == 'remove':
        if modelType == 'role':
            self.roles.remove(activeInstance)
        elif modelType == 'permission':
            self.permissions.remove(activeInstance)
    db.session.add(self)
    db.session.commit()

    if action == 'add':
        return True, f"{activeInstance} added to {self}."
    if action == 'remove':
        return True, f"{activeInstance} removed from {self}. {responseDict[modelType]['removed']}"


def _createUserMixin(ext, db):

    def get_model(model, db=db):
        for c in db.Model._decl_class_registry.values():
            if hasattr(c, '__table__') and c.__tablename__ == ext.table_dict[model]:
                return c

    class UserMixinP(db.Model):
        __tablename__ = ext.user_table
        __abstract__ = True

        @declared_attr
        def roles(cls):
            return db.relationship(ext.role_model, secondary='user_role_links')

        @declared_attr
        def permissions(cls):
            return db.relationship(ext.perm_model, secondary='user_permission_links')

        def addRole(self, role=None, roleName=None, kvDict=None):
            """
            Grants a role to the user from which permissions will be inherited.  Priority to arguments goes role,
            roleName, then roleId.

            :param role: (Role) A role instance
            :param roleName: (str) A role instance name
            :param kvDict: A dictionary of role model keys/values.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            return _modelActionBase(self, instance=role, instanceName=roleName, kvDict=kvDict,
                                    model=get_model('role'), db=db, action='add', modelType='role')

        def removeRole(self, role=None, roleName=None, kvDict=None):
            """
            Removes a role from the user.  This only removes a directly applied role; the user may still have the
            role through another role's inherited roles.

            :param role: (Role) A role instance
            :param roleName: (str) A role instance name
            :param kvDict: A dictionary of role model keys/values.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            return _modelActionBase(self, instance=role, instanceName=roleName, kvDict=kvDict,
                                    model=get_model('role'), db=db, action='remove', modelType='role')

        def addPermission(self, permission=None, permName=None, kvDict=None):
            """
            Adds a direct permission to the user.

            :param permission: (Permission) A permission instance
            :param permName: (str) A permission instance name
            :param kvDict: A dictionary of permission model keys/values.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            return _modelActionBase(self, instance=permission, instanceName=permName, kvDict=kvDict,
                                    model=get_model('perm'), db=db, action='add', modelType='permission')

        def removePermission(self, permission=None, permName=None, kvDict=None):
            """
            Removes a direct permission from the user.  This only removes the direct permission; if the permission
            is also granted through an assigned Role, the user will still have the permission.

            :param permission: (Permission) A permission instance
            :param permName: (str) A permission instance name
            :param kvDict: A dictionary of permission model keys/values.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            return _modelActionBase(self, instance=permission, instanceName=permName, kvDict=kvDict,
                                    model=get_model('perm'), db=db, action='remove', modelType='permission')

        def allPermissionsRoles(self):
            """
            Returns a tuple containing a set of all user permission names, and a set of all direct and inherited
            role names.

            :return: (permission_name_set, role_name_set)
            """
            permSet = set()
            for p in self.permissions:
                permSet.add(p.name)
            roleNameSet = set()
            for role in self.roles:
                rolePerms = set()
                roleNameSet.add(role.name)
                for perm in role.permissions:
                    rolePerms.add(perm.name)
                if role.parents:
                    tempRoleNameSet = set()
                    for role in role.parents:
                        if role.name in roleNameSet:
                            continue
                        tempRolePerms, tempRoleNameSet = role.allPermissionsRoles(previousRoleNames=roleNameSet)
                        rolePerms = rolePerms | tempRolePerms
                        roleNameSet = roleNameSet | tempRoleNameSet
                permSet = permSet | rolePerms

            return permSet, roleNameSet

    return UserMixinP


def _createRoleMixin(ext, db):

    def get_model(model, db=db):
        for c in db.Model._decl_class_registry.values():
            if hasattr(c, '__table__') and c.__tablename__ == ext.table_dict[model]:
                return c

    def inheritedRoles(role, roleNameSet=None):
        if not roleNameSet:
            roleNameSet = set()

        if role.name in roleNameSet:
            return set()

        roleNameSet.add(role.name)
        for subRole in role.parents:
            roleNameSet = roleNameSet | inheritedRoles(subRole, roleNameSet)

        return roleNameSet

    class RoleMixinP(db.Model):
        __tablename__ = ext.role_table
        __abstract__ = True
        name = db.Column(db.String(64), unique=True)
        description = db.Column(db.Text)

        @declared_attr
        def users(cls):
            return db.relationship(ext.user_model, secondary='user_role_links')

        @declared_attr
        def permissions(cls):
            return db.relationship(ext.perm_model, secondary='role_permission_links')

        @declared_attr
        def parents(cls):
            """
            List of roles the role inherits from.
            """
            return db.relationship(ext.role_model, secondary='role_links',
                                   primaryjoin=f"RoleLink.role_id==%s.{ext.role_pk}" % cls.__name__,
                                   secondaryjoin=f"RoleLink.parent_id==%s.{ext.role_pk}" % cls.__name__,
                                   backref="children")

        def __repr__(self):
            return '<Role %r>' % self.name

        def inheritRole(self, role=None, roleName=None, roleId=None):
            """
            Add a role from which permissions will be inherited.  Checks to make sure not trying to inherit itself,
            and itself is not inherited down the line.  Priority to arguments goes role, roleName, then roleId.

            :param role: (Role) A role instance
            :param roleName: (str) A role instance name
            :param roleId: A role primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """

            roleModel = get_model('role')

            if role:
                try:
                    if self.name == role.name:
                        return False, f'Role cannot inherit itself.'
                except AttributeError:
                    return False, f'{role} is not a valid Role.'
                inheritedRole = role
            elif roleName:
                if self.name == str(roleName):
                    return False, f'Role cannot inherit itself.'
                inheritedRole = roleModel.query.filter_by(name=roleName).first()
                if not inheritedRole:
                    return False, f'{roleName} is not a valid Role name.'
            elif roleId:
                if self.id == int(roleId):
                    return False, f'Role cannot inherit itself.'
                inheritedRole = roleModel.query.filter_by(**{ext.role_pk: roleId}).first()
                if not inheritedRole:
                    return False, f'{roleName} is not a valid Role name.'
            else:
                return False, 'One of arguments role, roleName, or roleId must be specified.'

            currentInheritedRoles = inheritedRoles(self)

            if inheritedRole.name in currentInheritedRoles:
                return False, f"<Role '{self.name}'> already inherits from <Role '{inheritedRole.name}'>."

            self.parents.append(inheritedRole)
            db.session.add(self)
            db.session.commit()

            return True, f"<Role '{self.name}'> now inherits from <Role '{inheritedRole.name}'>."

        def removeInheritedRole(self, role=None, roleName=None, roleId=None):
            """
            Remove a role from which permissions were inherited.  Checks to make sure not trying to inherit itself,
            and itself is not inherited down the line.  Priority to arguments goes role, roleName, then roleId.
            :param role: (Role) A role instance
            :param roleName: (str) A role instance name
            :param roleId: A role primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """

            roleModel = get_model('role')

            if role:
                try:
                    if self.name == role.name:
                        return False, f'Role cannot remove itself.'
                except AttributeError:
                    return False, f'{role} is not a valid Role.'
                inheritedRole = role
            elif roleName:
                if self.name == str(roleName):
                    return False, f'Role cannot remove itself.'
                inheritedRole = roleModel.query.filter_by(name=roleName).first()
                if not inheritedRole:
                    return False, f'{roleName} is not a valid Role name.'
            elif roleId:
                if self.id == int(roleId):
                    return False, f'Role cannot remove itself.'
                inheritedRole = roleModel.query.filter_by(**{ext.role_pk: roleId}).first()
                if not inheritedRole:
                    return False, f'{roleName} is not a valid Role name.'
            else:
                return False, 'One of arguments role, roleName, or roleId must be specified.'

            currentInheritedRoles = inheritedRoles(self)

            if inheritedRole.name not in currentInheritedRoles:
                return False, f"<Role '{self.name}'> does not directly inherit from <Role '{inheritedRole.name}'>."

            self.parents.remove(inheritedRole)
            db.session.add(self)
            db.session.commit()

            return True, f"<Role '{self.name}'> no longer inherits directly from <Role '{inheritedRole.name}'>. " \
                f"NOTE it may still inherit the Role (or the Role's permissions) " \
                f"through another inherited Role's inherited Roles."

        def addPermission(self, permission=None, permName=None, kvDict=None):
            """
            Adds a permission to the role.

            :param permission: (Permission) A permission instance
            :param permName: (str) A permission instance name
            :param kvDict: A dictionary of permission model keys/values.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            return _modelActionBase(self, instance=permission, instanceName=permName, kvDict=kvDict,
                                    model=get_model('perm'), db=db, action='add', modelType='permission')

        def removePermission(self, permission=None, permName=None, kvDict=None):
            """
            Removes a permission from the role.

            :param permission: (Permission) A permission instance
            :param permName: (str) A permission instance name
            :param kvDict: A dictionary of permission model keys/values.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            return _modelActionBase(self, instance=permission, instanceName=permName, kvDict=kvDict,
                                    model=get_model('perm'), db=db, action='remove', modelType='permission')

        def allPermissionsRoles(self, previousRoleNames=None):
            """
            Returns a tuple containing a set of all role permission names, and a set including the role name and all
            inherited role names.

            :return: (permission_name_set, role_name_set)
            """
            rolePermsSet = set()
            if not previousRoleNames:
                previousRoleNames = set()

            # if role has already been counted, end recursion
            if self.id in previousRoleNames:
                return set(), set()

            previousRoleNames.add(self.name)

            for perm in self.permissions:
                rolePermsSet.add(perm.name)

            for subRole in self.parents:
                if subRole.name in previousRoleNames:
                    continue
                tempRolePermSet, tempRoleNames = subRole.allPermissionsRoles(previousRoleNames=previousRoleNames)
                rolePermsSet = rolePermsSet | tempRolePermSet
                previousRoleNames = previousRoleNames | tempRoleNames

            return rolePermsSet, previousRoleNames

    return RoleMixinP


def _createPermissionMixin(ext, db):

    class PermissionMixinP(db.Model):
        __tablename__ = ext.perm_table
        __abstract__ = True
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(64), unique=True)
        description = db.Column(db.Text)

        @declared_attr
        def users(cls):
            return db.relationship(ext.user_model, secondary='user_permission_links')

        @declared_attr
        def roles(cls):
            return db.relationship(ext.role_model, secondary='role_permission_links')

        def __repr__(self):
            return '<Permission %r>' % self.name

    return PermissionMixinP

