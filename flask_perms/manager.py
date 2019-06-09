import os
import sys

from flask import current_app, url_for
from pprint import pprint

from app import db
from .mixins.models import Role, Permission, User
from .settings import ROOT_ROLE, defaultPermissions  # PERMISSION_FILE, ROLE_FILE
from .parsers import TemplateParser, PyMain


class PermissionManager:
    def __init__(self, path=None, rootRole=ROOT_ROLE):
        self.templates = {}  # Raw Template Dict, organized by html
        self.routesByFile = {}  # Raw Code Dict, organized by python file.
        self.permChecks = []
        self.routesByBlueprint = {}  # Dict rewrite of routesByFile, re-oganized by Blueprint.  Include template info.
        self.usedPerms = set()  # Perms found in the app as a set
        self.dbPerms = []  # List of Permission objects found in the db
        self.dbPermNames = set()  # Perm names found in the db (as a set).
        self.roles = []  # List of Role objects found in the db
        self.roleNames = set()  # Role names found in the db (as a set).
        self.users = []  # List of User objects found in the db
        self.usedRoles = set()  # Roles specified in the app (as a set).
        self.missingPerms = set()  # Permissions specified in the app but not present in db (as a set).
        self.unutilizedPerms = set()  # Permissions specified in the db but not present in app (as a set).
        self.missingRoles = set()  # Roles specified in the app but not present in the db (as a set).
        self.appRoutes = {}  # dict of all app routes, with note of if protected.  by blueprint: route: {protected,
        self.rootRole = rootRole  # Name of the Role designated to function as root control.
        self.defaultPerms = set([perm for perm in defaultPermissions])
        self.userInfo = {}
        self.roleInfo = {}


        if path:
            self.path = path
        elif current_app.root_path:
            self.path = current_app.root_path
        else:
            self.path = os.path.dirname(sys.modules['__main__'].__file__)

    def init(self):
        self.dbParse()
        self.codeParse()
        self.addRolePerms()
        self.integrateRoutesTemplates()
        self.remapToBlueprint()
        # self.addDefaultPermissions()
        self.appRouteParse()
        self.findUnprotectedRoutes()
        self.check_missing()

    def re_init(self):
        self.__init__()
        self.init()

    def addDefaultPermissions(self):
        perms = []
        for perm in defaultPermissions:
            if perm in self.dbPermNames:
                continue
            self.usedPerms.add(perm)
            perms.append(Permission(name=perm, description=defaultPermissions[perm]))

        db.session.add_all(perms)
        db.session.commit()

    def codeParse(self):
        tp = TemplateParser(path=self.path)
        pp = PyMain(path=self.path)

        tp.run()
        pp.run()
        self.templates = tp.output
        self.routesByFile = pp.output
        self.permChecks = pp.permChecks

    def integrateRoutesTemplates(self):
        """
        Parses declared Permissions and Roles in the app python code.
        :return:
        """

        def add_template_to_subLevel(subLevel, template):
            for perm in subLevel['permissions']:
                self.usedPerms.add(perm)
            for role in subLevel['roles']:
                self.usedRoles.add(role)
            if template in subLevel['templates']:
                subLevel['templates'][template] = self.templates[template]
            for subLevel2 in subLevel['sub_levels']:
                subLevel['sub_levels'][subLevel2] = add_template_to_subLevel(subLevel['sub_levels'][subLevel2], template)
            return subLevel

        # Add template declared permissions to usedPerms Set
        for template in self.templates:
            useTempDict = {}
            for use in list(self.templates[template]):
                useTempDict[use] = self.templates[template][use]

                for perm in self.templates[template][use]['permissions']:
                    self.usedPerms.add(perm)
                del self.templates[template][use]

            self.templates[template]['uses'] = useTempDict
            self.templates[template]['renders'] = {}

            # add template information to routes
            for file in self.routesByFile:
                for bp in self.routesByFile[file]:
                    for route in self.routesByFile[file][bp]:
                        for perm in self.routesByFile[file][bp][route]['permissions']: # add route permissions to usedPerms set
                            self.usedPerms.add(perm)
                        for role in self.routesByFile[file][bp][route]['roles']: # add route permissions to usedPerms set
                            self.usedRoles.add(role)


                        if template in self.routesByFile[file][bp][route]['templates']:
                            self.routesByFile[file][bp][route]['templates'][template]['uses'] = self.templates[template]['uses']
                            if bp not in self.templates[template]['renders'].keys():
                                self.templates[template]['renders'][bp] = {}
                            if route not in self.templates[template]['renders'][bp].keys():
                                self.templates[template]['renders'][bp][route] = {}
                            for key in self.routesByFile[file][bp][route]:
                                if key == 'sub_levels' or key == 'templates':
                                    pass
                                else:
                                    self.templates[template]['renders'][bp][route][key] = self.routesByFile[file][bp][route][key]
                            self.templates[template]['renders'][bp][route]['file'] = file

                            """
                            self.templates[template]['renders'][bp][route]['line_number'] = self.routesByFile[file][bp][route]['line_number']
                            self.templates[template]['renders'][bp][route]['other_decorators'] = self.routesByFile[file][bp][route]['other_decorators']
                            self.templates[template]['renders'][bp][route]['permissions'] = self.routesByFile[file][bp][route]['permissions']
                            self.templates[template]['renders'][bp][route]['roles'] = self.routesByFile[file][bp][route]['roles']
                            self.templates[template]['renders'][bp][route]['file'] = file
                            """

                        # Recursive check of sublevels
                        for subLevel in self.routesByFile[file][bp][route]['sub_levels']:
                            self.routesByFile[file][bp][route]['sub_levels'][subLevel] = add_template_to_subLevel(self.routesByFile[file][bp][route]['sub_levels'][subLevel], template)


        """
        # Generate dict of protected routes by blueprint, remap file to key in each route.
        for file in pp.output:
            for bp in pp.output[file]:
                if bp not in self.routesByBlueprint.keys():
                    self.routesByBlueprint[bp] = {}
                for route in pp.output[file][bp]:
                    if route in self.routesByBlueprint[bp].keys():
                        raise RuntimeError(f'<{route}> is referenced twice in blueprint {bp}')
                    self.routesByBlueprint[bp][route] = pp.output[file][bp][route]
                    self.routesByBlueprint[bp][route]['file'] = file
        """

    def remapToBlueprint(self):
        self.routesByBlueprint = {}
        for file in self.routesByFile:
            for bp in self.routesByFile[file]:
                if bp not in self.routesByBlueprint.keys():
                    self.routesByBlueprint[bp] = {}
                for route in self.routesByFile[file][bp]:
                    if route in self.routesByBlueprint[bp].keys():
                        raise RuntimeError(f'<{route}> is referenced twice in blueprint {bp}')
                    self.routesByBlueprint[bp][route] = self.routesByFile[file][bp][route]
                    self.routesByBlueprint[bp][route]['file'] = file

    def dbParse(self):
        """
        Parses declared Permissions and Roles in the app database.
        :return:
        """
        self.roles = []
        for role in Role.query.all():
            self.roles.append(role)
        roleNameList = []
        for role in self.roles:
            roleNameList.append(role.name)
            if len(set(roleNameList)) != len(roleNameList):
                raise AssertionError('Roles with duplicate names exist in Role store.')
            self.roleNames = set(roleNameList)

        if self.rootRole not in self.roleNames:
            print(f'WARNING: given root Role <{self.rootRole}> not found in Role store.  '
                  f'It can be generated by running .init_permissions() or .create_root().', file=sys.stderr)

        self.dbPerms = Permission.query.all()

        self.users = []
        for user in User.query.all():
            self.users.append(user)
        dbPermNameList = []
        for perm in self.dbPerms:
            dbPermNameList.append(perm.name)
            if len(set(dbPermNameList)) != len(dbPermNameList):
                raise AssertionError('Permissions with duplicate values exist in Permission store.')
            self.dbPermNames = set(dbPermNameList)

    def appRouteParse(self):
        """
        Parses a dict of all routes in the app. returns {bp: {route: {'protected': None, 'url': route_url_path}
        :return:
        """
        with current_app.test_request_context():
            for rule in current_app.url_map.iter_rules():
                options = {}
                for arg in rule.arguments:
                    options[arg] = "[{0}]".format(arg)
                url=url_for(rule.endpoint, **options)
                if "." in rule.endpoint:
                    bp, route = rule.endpoint.split(sep='.')
                else:
                    bp = 'NONE'
                    route = rule.endpoint
                if bp not in self.appRoutes.keys():
                    self.appRoutes[bp] = {}
                self.appRoutes[bp][route] = {'protected': None, 'url': url}

    def findUnprotectedRoutes(self):

        # ToDo change this over to include permissions from specified required roles
        for bp in self.routesByBlueprint:
            for route in self.routesByBlueprint[bp]:
                if self.routesByBlueprint[bp][route]['permissions'] and route in self.appRoutes[bp].keys():
                    self.appRoutes[bp][route]['protected'] = self.routesByBlueprint[bp][route]['permissions']

    def check_missing(self):
        self.missingPerms = self.usedPerms - self.dbPermNames
        self.unutilizedPerms = self.dbPermNames - self.usedPerms - self.defaultPerms
        self.missingRoles = self.usedRoles - self.roleNames

    def addRolePerms(self):
        """
        add role based permissions to routesByFile dict., and generate 'all_permissions' key containing set of
        permission derived from permission list and roles.
        Also, generates a traceback of templates by way of bp/route/ifstatemtns that
        :return:
        """

        def parse_subLevel(subLevel):
            for roleName in subLevel['roles']:
                for role in self.roles:
                    if role.name == roleName:
                        subLevel['roles'][roleName] = role.allPermissionsRoles()[0]
                        for perm in subLevel['roles'][roleName]:
                            subLevel['all_permissions'].add(perm)
            for subLevel2 in subLevel['sub_levels']:
                subLevel['sub_levels'][subLevel2] = parse_subLevel(subLevel['sub_levels'][subLevel2])
            return subLevel

        for file in self.routesByFile:
            for bp in self.routesByFile[file]:
                for route in self.routesByFile[file][bp]:
                    # add route perms to all_permissions
                    self.routesByFile[file][bp][route]['all_permissions'] = set()
                    for perm in self.routesByFile[file][bp][route]['permissions']:
                        self.routesByFile[file][bp][route]['all_permissions'].add(perm)

                    # add route role perms, and add to all_permissions
                    for roleName in self.routesByFile[file][bp][route]['roles']:
                            for role in self.roles:
                                if role.name == roleName:
                                    self.routesByFile[file][bp][route]['roles'][roleName] = role.allPermissionsRoles()[0]
                                    for perm in self.routesByFile[file][bp][route]['roles'][roleName]:
                                        self.routesByFile[file][bp][route]['all_permissions'].add(perm)

                    # Recursive check of sublevels
                    for subLevel in self.routesByFile[file][bp][route]['sub_levels']:
                        self.routesByFile[file][bp][route]['sub_levels'][subLevel] = parse_subLevel(self.routesByFile[file][bp][route]['sub_levels'][subLevel])

    def generateUserAccessTree(self):
        # generate list of

        for user in self.users:
            pass

    def generateRoleAccessTree(self):
        pass



    def generate_unprotected_appRoute(self):
        # check permission status of all app routes
        self.unprotectedRoutes = {}
        # add permission status to appRoute dict, generate dict/list of unprotected routes
        for bp in self.appRoutes:
            if bp in self.routesByBlueprint:
                for route in self.appRoutes[bp]:
                    if route in self.routesByBlueprint[bp]:
                        if self.routesByBlueprint[bp][route]['permissions']:
                            self.appRoutes[bp][route]['protected'] = True
                        else:
                            if bp not in self.unprotectedRoutes.keys():
                                self.unprotectedRoutes[bp] = []
                            self.unprotectedRoutes[bp].append(route)
                            self.appRoutes[bp][route]['protected'] = False
                    else:
                        if bp not in self.unprotectedRoutes.keys():
                            self.unprotectedRoutes[bp] = []
                        self.unprotectedRoutes[bp].append(route)
                        self.appRoutes[bp][route]['protected'] = False
            else:
                if bp not in self.unprotectedRoutes.keys():
                    self.unprotectedRoutes[bp] = []
                for route in self.appRoutes[bp]:
                    self.unprotectedRoutes[bp].append(route)
                    self.appRoutes[bp][route]['protected'] = False

    def report(self):

        good = '['+u'\u221A'+']'
        bad = '['+u'\u04FE'+']'

        print('Permission report:')
        print('- - - - - - - - - - - - - - - - - - - -')
        if self.missingPerms:
            print(bad+'--Permissions used in app not found in Permission store--'+bad)
            for perm in self.missingPerms:
                print(f'<{perm}> ,', end='')
            print('')
            print('------------------------------------')
        else:
            print(good+'--All used Permissions declared--'+good)
        print('')
        if self.unutilizedPerms:
            print(bad+'--Unutilized Permissions found in Permission store--'+bad)
            for perm in self.unutilizedPerms:
                print(f'<{perm}> ,', end='')
            print('')
            print('------------------------------------')
        else:
            print(good+'--All declared Permissions used--'+good)

        print('')
        print(f'Root Role specified as <{self.rootRole}>')
        root = Role.query.filter_by(name=self.rootRole).first()
        if not root:
            print(bad+f'--<{self.rootRole}> not found in Role store--'+bad)
        else:
            if not self.usedPerms.issubset(set(root.allPermissionsRoles()[0])):
                print(f'!--<{self.rootRole}> missing used Permissions--!')
                for perm in self.usedPerms - root.allPermissionsRoles()[0]:
                    print(f'<{perm}> ,', end='')
                print('')
                print('------------------------------------')
            else:
                print(good+f'--All used Permissions currently assigned to <{self.rootRole}>')
            print('')
            if self.dbPermNames - root.allPermissionsRoles()[0]:
                print(bad+f'--<{self.rootRole}> missing declared db Permissions--!')
                for perm in self.dbPermNames - root.allPermissionsRoles()[0]:
                    print(f'<{perm}> ,', end='')
                print('')
                print('------------------------------------')
            else:
                print(good+f'--All declared Permissions currently assigned to <{self.rootRole}>')
        print('')
        print('---Routes with undeclared Permissions---')

        for bp in self.routesByBlueprint:
            print('-  -  -  -  -  -  -')
            print(f'Blueprint: {bp}')
            bpClean = True
            for route in self.routesByBlueprint[bp]:
                if not set(self.routesByBlueprint[bp][route]['permissions']).issubset(self.dbPermNames):
                    bpClean = False
                    print(f'\t{route} in {self.routesByBlueprint[bp][route]["file"]}'
                          f'({self.routesByBlueprint[bp][route]["line_number"]}): '
                          f'{self.dbPermNames - set(self.routesByBlueprint[bp][route]["permissions"])}')
            if bpClean:
                print('\t'+good+'--All route permissions declared')
        print('---------------------------------------')
        print('')

        print('---Templates with undeclared Permissions---')

        for template in self.templates:
            templatePerms = []
            for usage in self.templates[template]['uses']:
                templatePerms.extend(self.templates[template]['uses'][usage]['permissions'])
            if not set(templatePerms).issubset(self.dbPermNames):
                templateRoutes = []
                for bp in self.templates[template]['renders']:
                    for route in self.templates[template]['renders'][bp]:
                        templateRoutes.append(bp+"."+route)
                print(f'{template} rendered by ')

        print('')
        print('---Unpermissioned Routes---')
        for bp in self.appRoutes:
            print('-  -  -  -  -  -  -')
            print(f'Blueprint: {bp}')
            bpClean = True
            for route in self.appRoutes[bp]:
                if self.appRoutes[bp][route]['protected'] is None:
                    bpClean = False
                    print(f'\t{route} \t\t\t url {self.appRoutes[bp][route]["url"]}')
            if bpClean:
                print('\t'+good+'--(All Routes Permissioned)')
        print('---------------------------------------')
        print('')

        print('---Users with Roles/Permissions---')
        for user in self.users:
            if user.permissions or user.roles:
                print(user)
                if user.roles:
                    print('   Roles:\n\t', end='')
                    for i, role in enumerate(user.roles):
                        if i+1 == len(user.roles):
                            print(role.name)
                        else:
                            print(role.name, end=", ")

                if user.permissions:
                    print('   Explicit Permissions:\n\t', end='')
                    for i, perm in enumerate(user.permissions):
                        if i+1 == len(user.permissions):
                            print(perm.name)
                        else:
                            print(perm.name, end=", ")
                print('')
        print('---------------------------------------')
        print('')





        # generate dict permissions with where they're used, set of missing permissions

        # 1) for each route, check if permission declared. if not, add a key 'Missing_Perm' with list of missing permissions.
            # 1a) check if roles exist.  if not add a key 'Missing_Role
            # 1a) populate a new key 'All_Perms_Required' with declared permissions and role permissions
            # 1b) Populate a new key 'Users' with users with access. (check 'All_perms_required' against user's allPermissionsRoles()

        test = 1

    def init_permissions(self, fromApp=True, fromFile=True, createRoot=True):
        """
        wrapper for populate_from_app, populate_from_file, and create_root.
        :param fromApp:
        :param fromFile:
        :param createRoot:
        :return:
        """
        if fromApp:
            self.populate_from_app()
        if createRoot:
            self.create_root()

    def populate_from_app(self):
        """
        Uses the parsed data from routes and templates to populate the Permissions model.
        """
        perms = []
        if self.missingPerms:
            print('Adding missing permissions from app', file=sys.stderr)
            for perm in self.missingPerms:
                perms.append(Permission(name=perm))
            db.session.add_all(perms)
            db.session.commit()
        else:
            print('No declared app permissions missing from Permission store.', file=sys.stderr)

        self.dbParse()  # reset db-based attributes
        self.check_missing()  # reset intersections of db-perms and app=perms

    def populate_from_file(self, file):
        pass

    def create_root(self):
        """
        First, check if a Role with name == to rootName exists, instantiate one if not.  Then, make sure missingPerms is
         empty.  If not, rerun populate_from_app.  Then, add any perms to the role not already present.
        """

        if self.rootRole not in self.roleNames:
            print(f'Specified root Role <{self.rootRole}> not found in Role store; generating new role.')
            rootRole = Role(name=self.rootRole, description=f"{self.rootRole} role.  Has all permissions. "
                                                            f" Should be considered as root.")
        else:
            rootRole = Role.query.filter_by(name=self.rootRole).first()

        if self.missingPerms:
            self.populate_from_app()

        perms = Permission.query.all()
        rolePerms = rootRole.allPermissionsRoles()[0]

        for perm in perms:
            if perm.name in rolePerms:
                continue
            rootRole.addPermission(perm)

    def generate_user_info(self):
        """
        still to do:
        for each user,
            ---generate a dictionary of templates they have access to, and the traceback to the template.
            take a users permset, and walk the blueprint tree.  recursive algo that takes in permset and path thus far,
            and passes up a dict with {template: [finished path] }.
            ---generate list of accessible routes
            ---with the template dict above, generate list of allowed actions on template. and unallowed
        """
        def check_sub_level(subLevel, pathThusFar):
            pass
            #if all_permissions in userPermSet


        for user in self.users:
            self.userInfo[user] = {}
            userPermSet = user.allPermissionsRoles()[0]
            for bp in self.routesByBlueprint:
                for route in self.routesByBlueprint[bp]:
                    pass
                    """
                    first, generate a list of all routing paths by blueprint, and all route permutations without 
                    a route.  this will be used to determine if the user has full permissions in that route/bp for the
                    summary report.  also generate explicit routing permissions.
                    Would be also nice to see: If a user has access, determine the source of that access (roles, 
                    explicit permissions) 
                    first, check if user has route permissions. if so, add bp->route to list. maybe add user to a new 
                    key, users_with_access?  if a template, add as well.  if sublevels, list 
                    """



