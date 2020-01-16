
def _createRoleLinkModel(ext, db):

    class RoleLink(db.Model):
        __tablename__ = ext.role_link
        parent_id = db.Column(db.Integer, db.ForeignKey(ext.role_table + '.' + ext.role_pk), primary_key=True)
        role_id = db.Column(db.Integer, db.ForeignKey(ext.role_table + '.' + ext.role_pk), primary_key=True)

    return RoleLink


def _createCrossLinkModels(ext, db):

    # create foreign key strings
    # if schemas set, add schema precursor onto foreign key

    class UserPermissionLink(db.Model):
        __tablename__ = ext.user_perm_link
        user_id_num = db.Column(db.Integer, db.ForeignKey(ext.user_table + '.' + ext.user_pk), primary_key=True)
        perm_id_num = db.Column(db.Integer, db.ForeignKey(ext.perm_table + '.' + ext.perm_pk), primary_key=True)

    class RolePermissionLink(db.Model):
        __tablename__ = ext.role_perm_link
        role_id_num = db.Column(db.Integer, db.ForeignKey(ext.role_table + '.' + ext.role_pk), primary_key=True)
        perm_id_num = db.Column(db.Integer, db.ForeignKey(ext.perm_table + '.' + ext.perm_pk), primary_key=True)

    class UserRoleLink(db.Model):
        __tablename__ = ext.user_role_link
        user_id_num = db.Column(db.Integer, db.ForeignKey(ext.user_table + '.' + ext.user_pk), primary_key=True)
        role_id_num = db.Column(db.Integer, db.ForeignKey(ext.role_table + '.' + ext.role_pk), primary_key=True)

    return UserPermissionLink, RolePermissionLink, UserRoleLink
