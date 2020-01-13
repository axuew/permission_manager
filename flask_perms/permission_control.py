from functools import wraps
from flask import current_app, flash, redirect, url_for, abort, jsonify
from flask_login import current_user


def refreshPermissions():
    current_user.permSet = current_user.allPermissionsRoles()[0]


def _invalidRoleHandling(role, api):
    print(f'WARNING: {role} is not a valid Role, no Permissions parsed.')
    if 'view_permissions_errors' in current_user.permSet:
        if api:
            return jsonify({'error': f'Role <{role}> specified as required but not found in Role store.'}), 500
        else:
            flash(f'Role <{role}> specified as required but not found in Role store.', 'danger')
    elif api:
        return jsonify({'error': 'Internal Server Error'}), 500
    abort(500)


def _getPermsRequired(useType, permissions=None, roles=None, api=False):
    Role = current_app.extensions['flask_perms']._get_model('role')
    if not permissions and not roles:
        if useType == 'route_dec':
            raise ValueError('A permission_required decorator is missing any permissions or roles')
        elif useType == 'bp_dec':
            raise ValueError('A bp_permission_required decorator is missing any permissions or roles')
        elif useType == 'check':
            raise ValueError('Permission check is missing any permissions or roles')
        else:
            raise ValueError('Permission evaluation missing any permissions or roles')
    if permissions:
        permsRequired = set(permissions)
    else:
        permsRequired = set()
    if roles:
        for role in roles:
            localRole = Role.query.filter_by(name=role).first()
            if not localRole:
                _invalidRoleHandling(role, api)

            rolePerms = localRole.allPermissionsRoles()[0]
            for p in rolePerms:
                permsRequired.add(p.name) #ToDo Check against p.name
    return permsRequired


def _missingPermHandling(missingPerms, hide, api):
    if hide == "all":
        if api:
            return jsonify({'error': 'Not Found'}), 404
        else:
            abort(404)
    elif 'view_missing_permissions' in current_user.permSet:
        if api:
            return jsonify({'error': f'insufficient permissions', 'missing_permissions': list(missingPerms)}), 403
        else:
            flash(f'Insufficient permissions, missing: [{missingPerms}].', 'danger')
    else:
        if api:
            return jsonify({'error': 'unauthorized'}), 403
        else:
            flash('Unauthorized access.  Please check with an administrator.', 'danger')
    print('redirecting')
    return redirect(url_for('main.index'))  # ToDo Set this to a config variable


def _permissionRouteHandling(useType, permissions=None, roles=None, hide='', api=False):
    permsRequired = _getPermsRequired(useType, permissions, roles, api)

    refreshPermissions()

    missingPerms = permsRequired.difference(current_user.permSet)

    response = None
    if missingPerms:
        response = _missingPermHandling(missingPerms, hide, api)

    return response


def permissionCheck(permissions=None, roles=None, user=current_user, permSet=None, api=False):

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


    if user and permSet:
        raise ValueError('Only one of User model (user) or permission set (permSet) can be given: set user to None')
    elif user:
        permSet=user.allPermissionsRoles()[0]
    elif not permSet:
        raise ValueError('User model (user) or permission set (permSet) must be given')

    permsRequired = _getPermsRequired('check', permissions, roles, api)

    missingPerms = permsRequired.difference(permSet)

    if missingPerms and 'view_missing_permissions' in permSet:
        return False, missingPerms
    elif missingPerms:
        return False, []
    else:
        return True, []


def permission_required(permissions=None, roles=None, hide='', api=False):
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

            # get all required permissions
            if current_user.is_authenticated:

                response = _permissionRouteHandling('bp_dec', permissions, roles, hide, api)
                if response:
                    return response

                return f(*args, **kwargs)

            elif not hide:
                if api:
                    return jsonify({'error': 'unauthorized'}), 401
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('main.index'))  # ToDo Set this to a config variable
            else:
                if api:
                    return jsonify({}), 404
                abort(404)
        return decorated_function
    return decorator


def bp_permission_required(permissions=None, roles=None, hide='', func=None, api=False):

    if not func:
        raise ValueError('bp_permission_required called without decorated func')

    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user and current_user.is_authenticated:
            response = _permissionRouteHandling('bp_dec', permissions, roles, hide, api)
            if response:
                return response

            return func(*args, **kwargs)

        elif not hide:
            flash('Please Log in to access this page.', 'warning')
            return redirect(url_for('main.index'))
        else:
            if api:
                return jsonify({}), 404
            abort(404)
    return decorated_function
