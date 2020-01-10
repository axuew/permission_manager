from functools import wraps
from flask import app, current_app, flash, redirect, url_for, abort, jsonify
from flask_login import current_user


def permissionCheck(permissions=None, roles=None, user=current_user, permSet=None):

    """
    For checking user permissions outside of the context of a route decorator or template.  While a direct check against
     the user's permSet can be done, using this function adds integration into the Permission QC functionality.

    :param permissions: (list, set, string)
    :param roles: (list, set)
    :param user:
    :param permSet:
    :return: tuple with boolean specifying the user has required permissions, and if the user does not but does have
                the default 'view_missing_permissions' permission, a list of permission names they are missing from the
                check.
    """
    Role = current_app.extensions['flask_perms']._get_model('role')
    requiredPermissions = set()

    if user and permSet:
        raise ValueError('Only one of User model (user) or permission set (permSet) can be given')
    elif user:

        permSet=user.allPermissionsRoles()[0]
    elif not permSet:
        raise ValueError('User model (user) or permission set (permSet) must be given')

    if not permissions and not roles:
        raise ValueError('Permission check is missing any required permissions or roles')
    if permissions:
        permsRequired = set(permissions)
    else:
        permsRequired = set()

    if roles:
        for role in roles:
            localRole = Role.query.filter_by(name=role).first()
            if not localRole:
                if 'view_missing_permissions' in permSet:
                    flash(f'Role <{role}> specified during Permission check but not found in Role store.', 'danger')
                else:
                    flash('Unauthorized access.  Please check with an administrator.', 'danger')
                abort(500)
            rolePerms = role.allPermissionsRoles()[0]
            for p in rolePerms:
                permsRequired.add(p.name)

    missingPerms = permsRequired.difference(permSet)

    if missingPerms and 'view_missing_permissions' in permSet:
        return False, missingPerms
    elif missingPerms:
        return False, []
    else:
        return True, []


def permission_required(permissions=None, roles=None, hide=False):
    """
    Decorator for routing functions that limits access by permissions and roles.  if the user or user's roles do not
    have the proper permission, restrict access.

    :param permissions: (list, set) Specific permission names (strings) required for route access.
                                    ex: ['edit', 'view_admin_panel']
    :param roles: (list) If supplied, all the permissions associated with this role will be required for route access.
    :param hide: (bool) If True, Return a 404 if user is missing permissions (or is not logged in)
    :return: Allows route if current_user has proper set of permissions.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            Role = current_app.extensions['flask_perms']._get_model('role')
            # get all required permissions
            if current_user.is_authenticated:

                if not permissions and not roles:
                    raise ValueError('A permission_required decorator is missing any permissions or roles')
                if permissions:
                    permsRequired = set(permissions)
                else:
                    permsRequired = set()
                if roles:
                    for role in roles:
                        localRole = Role.query.filter_by(name=role).first()
                        if not localRole:
                            if 'view_permissions_errors' in current_user.permSet:
                                flash(f'Role <{role}> specified as required but not found in Role store.', 'danger')
                            print(f'WARNING: {role} is not a valid Role, no Permissions parsed.')
                            abort(500)
                        rolePerms = localRole.allPermissionsRoles()[0]
                        for p in rolePerms:
                            permsRequired.add(p)

                # get all user permissions
                refreshPermissions()

                missingPerms = permsRequired.difference(current_user.permSet)

                if missingPerms:
                    if hide == "all":
                        abort(404)
                    elif 'view_missing_permissions' in current_user.permSet:
                        flash(f'Insufficient permissions, missing: [{missingPerms}].', 'danger')
                    else:
                        flash('Unauthorized access.  Please check with an administrator.', 'danger')
                    return redirect(url_for('main.index')) # ToDo Set this to a config variable

                return f(*args, **kwargs)

            elif not hide:
                flash('Please Log in to access this page.', 'warning')
                return redirect(url_for('main.index'))  # ToDo Set this to a config variable
            else:
                abort(404)
        return decorated_function
    return decorator


def bp_permission_required(permissions=None, roles=None, hide='', func=None):

    if not func:
        raise ValueError('bp_permission_required called without decorated func')

    @wraps(func)
    def decorated_function(*args, **kwargs):
        Role = current_app.extensions['flask_perms']._get_model('role')
        if current_user and current_user.is_authenticated:
            if not permissions and not roles:
                raise ValueError('A bp_permission_required decorator is missing any permissions or roles')
            if permissions:
                permsRequired = set(permissions)
            else:
                permsRequired = set()
            if roles:
                for role in roles:
                    localRole = Role.query.filter_by(name=role).first()
                    if not localRole:
                        if 'view_permissions_errors' in current_user.permSet:
                            flash(f'Role <{role}> specified as required but not found in Role store.', 'danger')
                        print(f'WARNING: {role} is not a valid Role, no Permissions parsed.')
                        abort(500)
                    rolePerms = localRole.allPermissionsRoles()[0]
                    for p in rolePerms:
                        permsRequired.add(p)

            # get all user permissions
            refreshPermissions()

            missingPerms = permsRequired.difference(current_user.permSet)

            if missingPerms:
                if hide == 'all':
                    abort(404)
                elif 'view_missing_permissions' in current_user.permSet:
                    flash(f'Insufficient permissions, missing: [{missingPerms}].', 'danger')
                else:
                    flash('Unauthorized access.  Please check with an administrator.', 'danger')
                return redirect(url_for('main.index'))

            return func(*args, **kwargs)

        elif not hide:
            flash('Please Log in to access this page.', 'warning')
            return redirect(url_for('main.index'))
        else:
            abort(404)
    return decorated_function


def api_permission_required(permissions=None, roles=None, hide=False):
    """
    Decorator for RESTful API routing functions that limits access by permissions and roles.  if the user or user's
    roles do not have the proper permission, restrict access.

    :param permissions: (list, set) Specific permission names (strings) required for route access.
                                    ex: ['edit', 'view_admin_panel']
    :param roles: (list) If supplied, all the permissions associated with this role will be required for route access.
    :param hide: (bool) If True, Return a 404 if user is missing permissions (or is not logged in)
    :return: Allows route if current_user has proper set of permissions.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # get all required permissions
            if current_user.is_authenticated:

                if not permissions and not roles:
                    raise ValueError('A permission_required decorator is missing any permissions or roles')
                if permissions:
                    permsRequired = set(permissions)
                else:
                    permsRequired = set()
                if roles:
                    for role in roles:
                        localRole = Role.query.filter_by(name=role).first()
                        if not localRole:
                            print(f'WARNING: {role} is not a valid Role, no Permissions parsed.')
                            if 'view_permissions_errors' in current_user.permSet:
                                return jsonify({'error': f'Role <{role}> specified as required but not found in Role store.'}), 500
                            else:
                                return jsonify({}), 500
                        rolePerms = localRole.allPermissionsRoles()[0]
                        for p in rolePerms:
                            permsRequired.add(p)

                # get all user permissions
                refreshPermissions()

                missingPerms = permsRequired.difference(current_user.permSet)

                if missingPerms:
                    if hide == "all":
                        return abort(404)
                    elif 'view_missing_permissions' in current_user.permSet:
                        return jsonify({'message': f'Insufficient permissions, missing: [{missingPerms}].'}), 401
                    else:
                        return jsonify({'message': f'Unauthorized access.  Please check with an administrator.'}), 401

                return f(*args, **kwargs)

            elif not hide:
                return jsonify({'message': f'Login required.'}), 401
            else:
                abort(404)
        return decorated_function
    return decorator


def refreshPermissions():
    current_user.permSet = current_user.allPermissionsRoles()[0]

