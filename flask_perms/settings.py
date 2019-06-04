from flask import current_app

defaultPermissions = {'view_missing_permissions':
                          'Allows user to view what permissions they are missing when denied access.',

                      'view_permission_errors':
                          'Grants user notifications when permission handling errors occur.'
                      }

if "ROOT_ROLE" in current_app.config.keys():
    ROOT_ROLE = current_app.config['ROOT_ROLE']
else:
    ROOT_ROLE = "Head Admin"

if "IGNORE_EMPTY_PERMISSION_CHECKS" in current_app.config.keys():
    IGNORE_EMPTY = current_app.config['IGNORE_EMPTY_PERMISSION_CHECKS']
else:
    IGNORE_EMPTY = False

# PERMISSION_FILE

# ROLE_FILE

STORE_TYPE = 'DB'

USE_DB = True

USER_MODEL = "User"
ROLE_MODEL = "Role"
PERMISSION_MODEL = "Permission"

USE_SCHEMAS = False

USER_SCHEMA = ""