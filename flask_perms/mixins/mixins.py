from sqlalchemy.ext.declarative import declared_attr


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

        def addRole(self, role=None, roleName=None, roleId=None):
            """
            Grants a role to the user from which permissions will be inherited.  Priority to arguments goes role,
            roleName, then roleId.

            :param role: (Role) A role instance
            :param roleName: (str) A role instance name
            :param roleId: A role primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """

            roleModel = get_model('role')

            if role:
                try:
                    tempName = role.name
                    addedRole = role
                except AttributeError:
                    return False, f'{role} is not a valid Role.'

            elif roleName:

                addedRole = roleModel.query.filter_by(name=roleName).first()
                if not addedRole:
                    return False, f'{roleName} is not a valid Role name.'
            elif roleId:
                addedRole = roleModel.query.filter_by(**{ext.role_pk: roleId}).first()
                if not addedRole:
                    return False, f'{roleName} is not a valid Role name.'
            else:
                return False, 'One of arguments role, roleName, or roleId must be specified.'

            if addedRole in self.roles:
                return False, f"{self} already has {addedRole}."

            self.roles.append(addedRole)
            db.session.add(self)
            db.session.commit()

            return True, f"{addedRole} added to {self}."

        def removeRole(self, role=None, roleName=None, roleId=None):
            """
            Removes a role from the user.  This only removes a directly applied role; the user may still have the
            role through another role's inherited roles.

            :param role (Role): A role instance
            :param roleName (str): A role instance name
            :param roleId: A role primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            roleModel = get_model('role')

            if role:
                try:
                    removedRole = role
                except AttributeError:
                    return False, f'{role} is not a valid Role.'

            elif roleName:
                removedRole = roleModel.query.filter_by(name=roleName).first()
                if not removedRole:
                    return False, f'{roleName} is not a valid Role name.'
            elif roleId:
                removedRole = roleModel.query.filter_by(**{ext.role_pk: roleId}).first()
                if not removedRole:
                    return False, f'{roleName} is not a valid Role name.'
            else:
                return False, 'One of arguments role, roleName, or roleId must be specified.'

            if removedRole not in self.roles:
                return False, f"{self} does not directly have {removedRole}."

            self.roles.remove(removedRole)
            db.session.add(self)
            db.session.commit()

            return True, f"{removedRole} removed from {self}. NOTE it may still inherit the role " \
                f"(or the role's permissions) through another inherited role's inherited roles."

        def addPermission(self, permission=None, permName=None, permId=None):
            """
            Adds a direct permission to the user.

            :param permission (Permission): A permission instance
            :param permName (str): A permission instance name
            :param permId: A permission primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            permModel = get_model('perm')

            if permission:
                try:
                    tempName = permission.name
                    addedPerm = permission
                except AttributeError:
                    return False, f'{permission} is not a valid permission.'
            elif permName:
                addedPerm = permModel.query.filter_by(name=permName).first()
                if not addedPerm:
                    return False, f'{permName} is not a valid permission name.'
            elif permId:
                addedPerm = permModel.query.filter_by(**{ext.perm_pk: permId}).first()
                if not addedPerm:
                    return False, f'{permName} is not a valid permission name.'

            if addedPerm in self.permissions:
                return False, f'{self} already has {addedPerm}.'

            self.permissions.append(addedPerm)
            db.session.add(self)
            db.session.commit()

            return True, f'{addedPerm} added to {self}.'

        def removePermission(self, permission=None, permName=None, permId=None):
            """
            Removes a direct permission from the user.  This only removes the direct permission; if the permission
            is also granted through an assigned Role, the user will still have the permission.

            :param permission (Permission): A permission instance
            :param permName (str): A permission instance name
            :param permId: A permission primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """
            permModel = get_model('perm')

            if permission:
                try:
                    tempName = permission.name
                    removedPerm = permission
                except AttributeError:
                    return False, f'{permission} is not a valid permission.'
            elif permName:
                removedPerm = permModel.query.filter_by(name=permName).first()
                if not removedPerm:
                    return False, f'{permName} is not a valid permission name.'
            elif permId:
                addedPerm = permModel.query.filter_by(**{ext.perm_pk: permId}).first()
                if not addedPerm:
                    return False, f'{permName} is not a valid permission name.'

            if removedPerm not in self.permissions:
                return False, f'{self} does not directly have {removedPerm}.'

            self.permissions.remove(removedPerm)
            db.session.add(self)
            db.session.commit()

            return True, f'{removedPerm} removed from {self}. NOTE it may still be present in a given role.'

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
            :param role (Role): A role instance
            :param roleName (str): A role instance name
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

        def addPermission(self, permission=None, permName=None, permId=None):
            """
            Adds a permission to the role.

            :param permission (Permission): A permission instance
            :param permName (str): A permission instance name
            :param permId: A permission primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """

            permModel = get_model('perm')

            if permission:
                try:
                    tempName = permission.name
                    addedPerm = permission
                except AttributeError:
                    return False, f'{permission} is not a valid Permission.'
            elif permName:
                addedPerm = permModel.query.filter_by(name=permName).first()
                if not addedPerm:
                    return False, f'{permName} is not a valid Permission name.'
            elif permId:
                addedPerm = permModel.query.filter_by(**{ext.perm_pk: permId}).first()
                if not addedPerm:
                    return False, f'{permName} is not a valid Permission name.'

            if addedPerm in self.permissions:
                return False, f'{self} already has {addedPerm}.'

            self.permissions.append(addedPerm)
            db.session.add(self)
            db.session.commit()

            return True, f'{addedPerm} added to {self}.'

        def removePermission(self, permission=None, permName=None, permId=None):
            """
            Removes a permission from the role.

            :param permission (Permission): A permission instance
            :param permName (str): A permission instance name
            :param permId: A permission primary key value.
            :return: A tuple containing a boolean representing the success of the operation, and a response string.
            """

            permModel = get_model('perm')

            if permission:
                try:
                    tempName = permission.name
                    removedPerm = permission
                except AttributeError:
                    return False, f'{permission} is not a valid Permission.'
            elif permName:
                removedPerm = permModel.query.filter_by(name=permName).first()
                if not removedPerm:
                    return False, f'{permName} is not a valid Permission name.'
            elif permId:
                addedPerm = permModel.query.filter_by(**{ext.perm_pk: permId}).first()
                if not addedPerm:
                    return False, f'{permName} is not a valid Permission name.'

            if removedPerm not in self.permissions:
                return False, f'{self} does not directly have {removedPerm}.'

            self.permissions.remove(removedPerm)
            db.session.add(self)
            db.session.commit()

            return True, f'{removedPerm} removed from {self}. NOTE it may still be present in an inherited Role.'

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

