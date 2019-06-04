from flask import current_app

from app import db


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    roles = db.relationship('Role', secondary='user_role_links')
    permissions = db.relationship('Permission', secondary='user_permission_links')


    def addRole(self, role=None, roleName=None, roleId=None):
        """
        Add a role from which permissions will be inherited.  Checks to make sure not trying to inherit itself, and
        itself is not inherited down the line.  Priority to arguments goes role, roleName, then roleId.
        :param role:
        :param roleName:
        :param roleId:
        :return:
        """
        if role:
            try:
                tempName = role.name
                addedRole = role
            except AttributeError:
                return False, f'{role} is not a valid Role.'

        elif roleName:
            addedRole = Role.query.filter_by(name=roleName).first()
            if not addedRole:
                return False, f'{roleName} is not a valid Role name.'
        elif roleId:
            addedRole = Role.query.filter_by(id=roleId).first()
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
        if role:
            try:
                tempName = role.name
                removedRole = role
            except AttributeError:
                return False, f'{role} is not a valid Role.'

        elif roleName:
            removedRole = Role.query.filter_by(name=roleName).first()
            if not removedRole:
                return False, f'{roleName} is not a valid Role name.'
        elif roleId:
            removedRole = Role.query.filter_by(id=roleId).first()
            if not removedRole:
                return False, f'{roleName} is not a valid Role name.'
        else:
            return False, 'One of arguments role, roleName, or roleId must be specified.'

        if removedRole not in self.roles:
            return False, f"{self} does not directly have {removedRole}."


        self.roles.remove(removedRole)
        db.session.add(self)
        db.session.commit()

        return True, f"{removedRole} removed from {self}. NOTE it may still inherit the Role " \
            f"(or the Role's permissions) through another inherited Role's inherited Roles."

    def addPermission(self, permission=None, permName=None):
        if permission:
            try:
                tempName = permission.name
                addedPerm = permission
            except AttributeError:
                return False, f'{permission} is not a valid Permission.'
        elif permName:
            addedPerm = Permission.query.filter_by(name=permName).first()
            if not addedPerm:
                return False, f'{permName} is not a valid Permission name.'

        if addedPerm in self.permissions:
            return False, f'{self} already has {addedPerm}.'

        self.permissions.append(addedPerm)
        db.session.add(self)
        db.session.commit()

        return True, f'{addedPerm} added to {self}.'

    def removePermission(self, permission=None, permName=None):
        if permission:
            try:
                tempName = permission.name
                removedPerm = permission
            except AttributeError:
                return False, f'{permission} is not a valid Permission.'
        elif permName:
            removedPerm = Permission.query.filter_by(name=permName).first()
            if not removedPerm:
                return False, f'{permName} is not a valid Permission name.'

        if removedPerm not in self.permissions:
            return False, f'{self} does not directly have {removedPerm}.'

        self.permissions.remove(removedPerm)
        db.session.add(self)
        db.session.commit()

        return True, f'{removedPerm} removed from {self}. NOTE it may still be present in a given Role.'

    def allPermissionsRoles(self):
        """
        returns a tuple containing all user permissions, and all direct or inherited roles.
        :return:
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


class RoleLink(db.Model):
    __tablename__ = "role_links"
    parent_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)


def inheritedRoles(role, roleNameSet=None):
    if not roleNameSet:
        roleNameSet = set()

    if role.name in roleNameSet:
        return set()

    roleNameSet.add(role.name)
    for subRole in role.parents:
        roleNameSet = roleNameSet | inheritedRoles(subRole, roleNameSet)

    return roleNameSet


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.Text)
    users = db.relationship('User', secondary='user_role_links')
    permissions = db.relationship('Permission', secondary='role_permission_links')
    parents = db.relationship('Role', secondary='role_links', primaryjoin=RoleLink.role_id == id,
                                secondaryjoin=RoleLink.parent_id == id, backref="children")

    def __repr__(self):
        return '<Role %r>' % self.name

    def inheritRole(self, role=None, roleName=None, roleId=None):
        """
        Add a role from which permissions will be inherited.  Checks to make sure not trying to inherit itself, and
        itself is not inherited down the line.  Priority to arguments goes role, roleName, then roleId.
        :param role:
        :param roleName:
        :param roleId:
        :return:
        """
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
            inheritedRole = Role.query.filter_by(name=roleName).first()
            if not inheritedRole:
                return False, f'{roleName} is not a valid Role name.'
        elif roleId:
            if self.id == int(roleId):
                return False, f'Role cannot inherit itself.'
            inheritedRole = Role.query.filter_by(id=roleId).first()
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
        Remove a role from which permissions were inherited.  Checks to make sure not trying to inherit itself, and
        itself is not inherited down the line.  Priority to arguments goes role, roleName, then roleId.
        :param role:
        :param roleName:
        :param roleId:
        :return:
        """
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
            inheritedRole = Role.query.filter_by(name=roleName).first()
            if not inheritedRole:
                return False, f'{roleName} is not a valid Role name.'
        elif roleId:
            if self.id == int(roleId):
                return False, f'Role cannot remove itself.'
            inheritedRole = Role.query.filter_by(id=roleId).first()
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

    def addPermission(self, permission=None, permName=None):
        if permission:
            try:
                tempName = permission.name
                addedPerm = permission
            except AttributeError:
                return False, f'{permission} is not a valid Permission.'
        elif permName:
            addedPerm = Permission.query.filter_by(name=permName).first()
            if not addedPerm:
                return False, f'{permName} is not a valid Permission name.'

        if addedPerm in self.permissions:
            return False, f'{self} already has {addedPerm}.'

        self.permissions.append(addedPerm)
        db.session.add(self)
        db.session.commit()

        return True, f'{addedPerm} added to {self}.'

    def removePermission(self, permission=None, permName=None):
        if permission:
            try:
                tempName = permission.name
                removedPerm = permission
            except AttributeError:
                return False, f'{permission} is not a valid Permission.'
        elif permName:
            removedPerm = Permission.query.filter_by(name=permName).first()
            if not removedPerm:
                return False, f'{permName} is not a valid Permission name.'

        if removedPerm not in self.permissions:
            return False, f'{self} does not directly have {removedPerm}.'

        self.permissions.remove(removedPerm)
        db.session.add(self)
        db.session.commit()

        return True, f'{removedPerm} removed from {self}. NOTE it may still be present in an inherited Role.'

    def allPermissionsRoles(self, previousRoleNames=None):

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


class Permission(db.Model):
    __tablename__ = "permissions"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.Text)
    users = db.relationship('User', secondary='user_permission_links')
    roles = db.relationship('Role', secondary='role_permission_links')

    def __repr__(self):
        return '<Permission %r>' % self.name


class UserPermissionLink(db.Model):
    __tablename__ = "user_permission_links"
    user_id_num = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    perm_id_num = db.Column(db.Integer, db.ForeignKey('permissions.id'), primary_key=True)


class RolePermissionLink(db.Model):
    __tablename__ = "role_permission_links"
    role_id_num = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)
    perm_id_num = db.Column(db.Integer, db.ForeignKey('permissions.id'), primary_key=True)


class UserRoleLink(db.Model):
    __tablename__ = "user_role_links"
    user_id_num = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    role_id_num = db.Column(db.Integer, db.ForeignKey('roles.id'), primary_key=True)
