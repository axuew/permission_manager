import os
import sys
import ast

from flask import current_app, url_for
from pprint import pprint
from jinja2 import Environment, FileSystemLoader, meta, visitor

from app import db
from .mixins.models import Role, Permission, User
from .settings import ROOT_ROLE, defaultPermissions  # PERMISSION_FILE, ROLE_FILE




class PermissionManager:
    def __init__(self, path=None, rootRole=ROOT_ROLE):
        self.templates = {}  # Raw Template Dict, organized by html
        self.routesByFile = {}  # Raw Code Dict, organized by python file.
        self.routesByBlueprint = {}  # Dict rewrite of routesByFile, re-oganized by Blueprint.  Include template info.
        self.usedPerms = set()  # Perms found in the app as a set
        self.dbPerms = []  # List of Permission objects found in the db
        self.dbPermNames = set()  # Perm names found in the db (as a set).
        self.roles = {}  # List of Role objects found in the db
        self.roleNames = set()  # Role names found in the db (as a set).
        self.users = {}  # List of User objects found in the db
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

        self.dbParse()
        self.codeParse()
        self.addRolePerms()
        self.integrateRoutesTemplates()
        self.remapToBlueprint()
        # self.addDefaultPermissions()
        self.appRouteParse()
        self.findUnprotectedRoutes()
        self.check_missing()

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

    def integrateRoutesTemplates(self):
        """
        Parses declared Permissions and Roles in the app python code.
        :return:
        """


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

                        # ToDo need to rewrite this with recursive algo to allow checking of sub_levels
                        if template in self.routesByFile[file][bp][route]['templates']:
                            self.routesByFile[file][bp][route]['templates'][template] = self.templates[template]
                            if bp not in self.templates[template]['renders'].keys():
                                self.templates[template]['renders'][bp] = {}
                            if route not in self.templates[template]['renders'][bp].keys():
                                self.templates[template]['renders'][bp][route] = {}
                            self.templates[template]['renders'][bp][route]['line_number'] = self.routesByFile[file][bp][route]['line_number']
                            self.templates[template]['renders'][bp][route]['other_decorators'] = self.routesByFile[file][bp][route]['other_decorators']
                            self.templates[template]['renders'][bp][route]['permissions'] = self.routesByFile[file][bp][route]['permissions']
                            self.templates[template]['renders'][bp][route]['roles'] = self.routesByFile[file][bp][route]['roles']
                            self.templates[template]['renders'][bp][route]['file'] = file

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
        for role in Role.query.all():
            self.roles[role] = {}
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

        for user in User.query.all():
            self.users[user] = {}
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
                        subLevel['all_permissions'].add(perm for perm in subLevel['roles'][roleName])
            for subLevel2 in subLevel['sublevels']:
                subLevel['sublevels'][subLevel2] = parse_subLevel(subLevel)
            return subLevel

        for file in self.routesByFile:
            for bp in self.routesByFile[file]:
                for route in self.routesByFile[file][bp]:
                    # add route perms to all_permissions
                    self.routesByFile[file][bp][route]['all_permissions'] = set()
                    self.routesByFile[file][bp][route]['all_permissions'].add(perm for perm in self.routesByFile[file][bp][route]['permissions'])

                    # add route role perms, and add to all_permissions
                    for roleName in self.routesByFile[file][bp][route]['roles']:
                            for role in self.roles:
                                if role.name == roleName:
                                    self.routesByFile[file][bp][route]['roles'][roleName] = role.allPermissionsRoles()[0]
                                    self.routesByFile[file][bp][route]['all_permissions'].add(perm for perm in self.routesByFile[file][bp][route]['roles'][roleName])

                    # Recursive check of sublevels
                    for subLevel in self.routesByFile[file][bp][route]['sublevels']:
                        self.routesByFile[file][bp][route]['sublevels'][subLevel] = parse_subLevel(subLevel)

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
                    #check if user has route permissions






class TemplateParser:
    def __init__(self, path=None):
        self.output = {}
        self.roots = []
        self.htmlFiles = []
        if path:
            self.path = path
        else:
            self.path = os.path.dirname(sys.modules['__main__'].__file__)

    def run(self):
        self.output = {}
        self.roots = []
        self.htmlFiles = []

        # get all html files and paths in application
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file.endswith(".html"):
                    self.roots.append(root)
                    self.htmlFiles.append(file)

        for i in range(len(self.htmlFiles)):
            jinjaEnv = Environment(autoescape=False, loader=FileSystemLoader(self.roots[i]), trim_blocks=False)
            jinjaEnv.filters['is_subset'] = self.is_subset
            temp_source = jinjaEnv.loader.get_source(jinjaEnv, self.htmlFiles[i])
            self.parsed_content = jinjaEnv.parse(temp_source[0])

            analyzerH = _TemplateWalker()
            analyzerH.visit(self.parsed_content)
            if analyzerH.instances:
                pathAppend = ""
                rootDiv = self.roots[i].split(sep='\\')
                if current_app.template_folder in rootDiv:
                    templateIndex = rootDiv.index(current_app.template_folder)
                    if templateIndex < len(rootDiv)-1:
                        for j in range(templateIndex+1, len(rootDiv)):
                            pathAppend += rootDiv[j] + '/'

                self.output[pathAppend+self.htmlFiles[i]] = analyzerH.instances

    def printResults(self):
        pprint(self.output)

    @staticmethod
    def is_subset(checkSet, mainSet):
        checkSet = set(checkSet)
        mainSet = set(mainSet)
        if checkSet.issubset(mainSet):
            return True
        else:
            return False

    def listPerms(self):
        permList = []
        for page in self.output:
            for instance in page:
                permList.extend(instance['permissions'])
        return permList


class _TemplateWalker(visitor.NodeVisitor):

    def __init__(self):
        self.instances = {}
        self.counter = 0

    def visit_If(self, node):
        if hasattr(node.test, 'name'):
            if node.test.name == "is_subset":
                self.instances[node.lineno] = {}
                self.instances[node.lineno]['permissions'] = []
                for perm in node.test.node.items:
                    self.instances[node.lineno]['permissions'].append(perm.value)
                if node.elif_:
                    self.instances[node.lineno]['elif'] = node.elif_[0].lineno
                if node.else_:
                    self.instances[node.lineno]['else'] = node.else_[0].lineno

                self.instances[node.lineno]['permSet'] = node.test.args[0].node.name + '.' + node.test.args[0].attr
                # print('found!')
                # print(node.node.items[0].value)

import sys

class PyMain:

    def __init__(self, path=None):
        self.output = {}
        self.permChecks = []
        self.pyFiles = []
        self.nodes = []
        if path:
            self.path = path
        else:
            self.path = os.path.dirname(sys.modules['__main__'].__file__)

    def run(self):
        self.output = {}
        self.pyFiles = []
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file.endswith(".py"):
                    self.pyFiles.append(root + "\\" + file)

        for file in self.pyFiles:
            if os.path.split(file)[-1] == 'analyzer.py':
                continue
            with open(file, "r") as source:
                tree = ast.parse(source.read())

                permCheckAnalyzer = PermCheckAnalyzer()

                routeAnalyzer = RouteAnalyzer(permCheckAnalyzer.permChecks)
                routeAnalyzer.visit(tree)
                if routeAnalyzer.routes:
                    self.output[os.path.relpath(file, self.path)] = routeAnalyzer.routes
                    self.nodes.append(routeAnalyzer.nodes)
                    self.permChecks = routeAnalyzer.permChecks

    def printResults(self):
        pprint(self.output)

    def listDeclaredPerms(self):
        permList = []
        for file in self.output:
            for blueprint in file:
                for route in blueprint:
                    permList.extend(route['permissions'])
        return permList




class PermCheckAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.permChecks = {}

    def visit_Call(self, node):
        print("went to call function")
        if isinstance(node.func, ast.Name):
            if node.func.id == "blueprint_permission_required":
                pass
            if node.func.id == "permissionCheck":
                print('CALL FOUND PERMISSION CHECK:', node.lineno)
                self.permChecks[node.lineno] = {'permissions': [], 'roles': {}}
                # Get values if declared as args instead of kwargs
                if node.args:
                    for perm in node.args[0].elts:
                        self.permChecks[node.lineno]['permissions'].append(perm.s)
                    if len(node.args) > 1:
                        for role in node.args[1].elts:
                            self.permChecks[node.lineno]['roles'][role.s] = {}

                # get values if declared as kwargs
                for arg in node.keywords:
                    if arg.arg == "permissions":
                        for perm in arg.value.elts:
                            self.permChecks[node.lineno]['permissions'].append(perm.s)
                    elif arg.arg == "roles":
                        # ToDo finish roles tree walk
                        for role in arg.value.elts:
                            self.permChecks[node.lineno]['roles'][role.s] = {}
        self.generic_visit(node)



class RouteAnalyzer(ast.NodeVisitor):
    def __init__(self, permCheckDict):
        self.routes = {} # the parsed routing tree.
        self.permChecks = permCheckDict  # Before analysis, holds the passed in dict of all permissionCheck instances.
                                         # after analysis, this holds a dict of permission checks run outside of a
                                         # route context.

    def visit_FunctionDef(self, node):
        print("went to function function")
        # Finds all routes.
        # Get route info
        if node.decorator_list:
            if isinstance(node.decorator_list[0], ast.Call):
                if isinstance(node.decorator_list[0].func, ast.Attribute):
                    if node.decorator_list[0].func.attr == 'route':
                        # found a route declaration
                        blueprint = node.decorator_list[0].func.value.id # will just be 'app' if not a blueprint

                        # if the blueprint hasn't been seen yet, save to dict
                        if blueprint not in self.routes.keys():
                            self.routes[blueprint] = {}

                        # Save the route endpoint
                        self.routes[blueprint][node.name] = {'url': node.decorator_list[0].args[0].s,
                                                             'permissions': [], 'roles': {}, 'line_number': node.lineno,
                                                             'other_decorators': [], 'templates': {}, 'sub_levels': {}}

                        permFunc = False
                        for dec in node.decorator_list[1:]:
                            if isinstance(dec, ast.Call):
                                if isinstance(dec.func, ast.Name):
                                    if dec.func.id == 'permission_required':
                                        permFunc = True
                                        break
                        if permFunc:
                            # Found a permission_required decorated route.

                            # get the permission required info, and also other decorators present
                            for dec in node.decorator_list[1:]:
                                if isinstance(dec, ast.Call):
                                    if isinstance(dec.func, ast.Name):
                                        if dec.func.id == 'permission_required':

                                            if dec.args:
                                                for perm in dec.args[0].elts:
                                                    self.routes[blueprint][node.name]['permissions'].append(perm.s)
                                                if len(dec.args) > 1:
                                                    for role in dec.args[1].elts:
                                                        self.routes[blueprint][node.name]['roles'][role.s] = []

                                            if dec.keywords:
                                                for arg in dec.keywords:
                                                    if arg.arg == "permissions":
                                                        for perm in arg.value.elts:
                                                            self.routes[blueprint][node.name]['permissions'].append(perm.s)
                                                    elif arg.arg == "roles":
                                                        # ToDo finish roles tree walk
                                                        for role in arg.value.elts:
                                                            self.routes[blueprint][node.name]['roles'][role.s] = []
                                        else:
                                            self.routes[blueprint][node.name]['other_decorators'].append(dec.func.id)
                                    elif isinstance(dec.func, ast.Attribute):
                                        self.routes[blueprint][node.name]['other_decorators'].append(dec.func.attr)
                                elif isinstance(dec, ast.Name):
                                    self.routes[blueprint][node.name]['other_decorators'].append(dec.id)

                        # get templates served by route, and internal usages of permissionCheck:
                        for bodyNode in node.body:

                            # check if node is a direct route return.
                            if isinstance(bodyNode, ast.Return):
                                if isinstance(bodyNode.value, ast.Call):
                                    if isinstance(bodyNode.value.func, ast.Name):
                                        if bodyNode.value.func.id == 'render_template':
                                            self.routes[blueprint][node.name]['templates'][bodyNode.value.args[0].s] = {}

                            # check if node is an if statement
                            elif isinstance(bodyNode, ast.If):
                                permIf = self._if_Parse(bodyNode)
                                if permIf is not None:
                                    for element in permIf:
                                        self.routes[blueprint][node.name]['sub_levels'][element] = permIf[element]


                            # otherwise, walk the node looking for ifs and templates.
                            else:
                                for subBodyNode in ast.walk(bodyNode):
                                    # check for more ifs (which would be sublevels) and
                                    # templates (which would be route level templates)
                                    if isinstance(bodyNode, ast.Return):
                                        if isinstance(bodyNode.value, ast.Call):
                                            if isinstance(bodyNode.value.func, ast.Name):
                                                if bodyNode.value.func.id == 'render_template':
                                                    self.routes[blueprint][node.name]['templates'][bodyNode.value.args[0].s] = {}

                                        # check if node is an if statement
                                    elif isinstance(subBodyNode, ast.If):
                                        permIf = self._if_Parse(subBodyNode)
                                        if permIf is not None:
                                            for element in permIf:
                                                self.routes[blueprint][node.name]['sub_levels'][element] = permIf[element]

                            self.routes[blueprint][node.name]['sub_levels'] = self._clean_sublevel_dict(self.routes[blueprint][node.name]['sub_levels'])[0]

                            emptySubLevels = []

                            # if subLevel with nothing but templates. And move template up the tree and delete subLevel.
                            for subLevel in self.routes[blueprint][node.name]['sub_levels']:
                                if not self.routes[blueprint][node.name]['sub_levels'][subLevel]['permissions'] and not \
                                 self.routes[blueprint][node.name]['sub_levels'][subLevel]['roles'] and not \
                                 self.routes[blueprint][node.name]['sub_levels'][subLevel]['sub_levels']:
                                    emptySubLevels.append(subLevel)
                                    for template in self.routes[blueprint][node.name]['sub_levels'][subLevel]['templates'].keys():

                                        self.routes[blueprint][node.name]['templates'][template] = {}
                            for subLevel in emptySubLevels:
                                del self.routes[blueprint][node.name]['sub_levels'][subLevel]

        self.generic_visit(node)

    def _if_Parse(self, node):
        # walk the test attribute for permcheck
        permissions = []
        roles = {}
        templates = {}
        subLevels = {}
        otherElifs = []

        checkFound = False
        templateFound = False

        result = {}

        for testNode in ast.walk(node.test): # Get the if statement TEST permissions
            if isinstance(testNode, ast.Call):
                if isinstance(testNode.func, ast.Name):
                    if testNode.func.id == "permissionCheck":
                        checkFound = True
                        #found permissionCheck.

                        if node.lineno in self.permChecks.keys():
                            del self.permChecks[node.lineno]

                        # Get values if declared as args instead of kwargs
                        if testNode.args:
                            for perm in testNode.args[0].elts:
                                permissions.append(perm.s)
                            if len(testNode.args) > 1:
                                for role in testNode.args[1].elts:
                                    roles[role.s] = []

                        # get values if declared as kwargs
                        for arg in testNode.keywords:
                            if arg.arg == "permissions":
                                for perm in arg.value.elts:
                                    permissions.append(perm.s)
                            elif arg.arg == "roles":
                                # ToDo finish roles tree walk
                                for role in arg.value.elts:
                                    roles[role.s] = []
        for bodyNode in node.body:
            # check for additional if statements
            if isinstance(bodyNode, ast.If):
                subIf = self._if_Parse(bodyNode)
                if subIf is not None:
                    for element in subIf:
                        subLevels[element] = subIf[element]
            # check for template returns
            elif isinstance(bodyNode, ast.Return):
                if isinstance(bodyNode.value, ast.Call):
                    if isinstance(bodyNode.value.func, ast.Name):
                        if bodyNode.value.func.id == 'render_template':
                            templateFound = True
                            templates[bodyNode.value.args[0].s] = {}
            else:
                for subBodyNode in ast.walk(bodyNode):
                    # check for additional if statements
                    if isinstance(bodyNode, ast.If):
                        subIf = self._if_Parse(bodyNode)
                        if subIf is not None:
                            for element in subIf:
                                subLevels[element] = subIf[element]
                    # check for template returns
                    elif isinstance(bodyNode, ast.Return):
                        if isinstance(bodyNode.value, ast.Call):
                            if isinstance(bodyNode.value.func, ast.Name):
                                if bodyNode.value.func.id == 'render_template':
                                    templateFound = True
                                    templates[bodyNode.value.args[0].s] = {}

        for orelseNode in node.orelse:
            # check for elif statements
            if isinstance(orelseNode, ast.If):
                subIf = self._if_Parse(orelseNode)
                if subIf is not None:
                    for element in subIf:
                        otherElifs.append([element, subIf[element]])

            else:  # check for else statements, which would have routes without additional protections.
                for elseNode in ast.walk(orelseNode): # walk the nodes of the else statement.
                    if isinstance(orelseNode, ast.If):
                        subIf = self._if_Parse(orelseNode)
                        if subIf is not None: #these would be considered on the same level as elifs, so add them to the otherElifs list.
                            for element in subIf:
                                otherElifs.append([element, subIf[element]])
                    # check for template returns
                    elif isinstance(elseNode, ast.Return):
                        if isinstance(elseNode.value, ast.Call):
                            if isinstance(elseNode.value.func, ast.Name):
                                if elseNode.value.func.id == 'render_template':
                                    templateFound = True
                                    templates[elseNode.value.args[0].s] = {}


        # before passing up, clean up the sublevel dictionary:
        subLevels = self._clean_sublevel_dict(subLevels)[0]

        emptySubLevels = []

        # if subLevel with nothing but templates. And move template up the tree and delete subLevel.
        for subLevel in subLevels:
            if not subLevels[subLevel]['permissions'] and not subLevels[subLevel]['roles'] and not subLevels[subLevel]['sub_levels']:
                emptySubLevels.append(subLevel)
                for template in subLevels[subLevel]['templates'].keys():
                    templateFound = True
                    templates[template] = {}
        for subLevel in emptySubLevels:
            del subLevels[subLevel]

        if not checkFound and not templateFound and not otherElifs and not subLevels:
            return None

        result[node.lineno] = {'permissions': permissions, 'roles': roles, 'templates': templates, 'sub_levels': subLevels}

        for otherResult in otherElifs:
            result[otherResult[0]] = otherResult[1]

        return result

    def _clean_sublevel_dict(self, subLevelDict):

        usedLineNos = set()

        for subLevel in subLevelDict:
            if subLevelDict[subLevel]['sub_levels']:
                result = self._clean_sublevel_dict(subLevelDict[subLevel]['sub_levels'])
                subLevelDict[subLevel]['sub_levels'] = result[0]
                usedLineNos = usedLineNos.union(result[1])

        for subLevel in usedLineNos:
            if subLevel in subLevelDict.keys():
                del subLevelDict[subLevel]

        usedLineNos.add(lineNos for lineNos in subLevelDict.keys())

        return subLevelDict, usedLineNos




    def report(self):
        pprint(self.stats)


if __name__ == "__main__":
    print('Analyzing project...')
    pyAnalysis = PyMain(path=os.curdir)
    pyAnalysis.run()
    print('Summary of permissioned routes by file/blueprint:')
    pyAnalysis.printResults()

    jinjaAnalysis = TemplateParser(path=os.curdir)
    jinjaAnalysis.run()
    print('Summary of permissioned templates by file/line:')
    jinjaAnalysis.printResults()


