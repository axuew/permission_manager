import os
import sys
import ast

from flask import current_app, url_for
from pprint import pprint
from jinja2 import Environment, FileSystemLoader, visitor

from app import db
from flask_perms.mixins.models import Role, Permission, User
from .settings import ROOT_ROLE, defaultPermissions  #, PERMISSION_FILE, ROLE_FILE


class PermissionManager:
    def __init__(self, path=None, rootRole=ROOT_ROLE):
        self.templates = {} # Raw Template Dict, organized by html
        self.routesByFile = {} # Raw Code Dict, organized by python file.
        self.routesByBlueprint = {} # Dict rewrite of routesByFile, re-oganized by Blueprint.  Include template info.
        self.usedPerms = set() # Perms found in the app as a set
        self.dbPerms = [] # List of Permission objects found in the db
        self.dbPermNames = set() # Perm names found in the db (as a set).
        self.roles = [] # List of Role objects found in the db
        self.roleNames = set() # Role names found in the db (as a set).
        self.users = [] # List of User objects found in the db
        self.usedRoles = set() # Roles specified in the app (as a set).
        self.missingPerms = set() # Permissions specified in the app but not present in db (as a set).
        self.unutilizedPerms = set() # Permissions specified in the db but not present in app (as a set).
        self.missingRoles = set() # Roles specified in the app but not present in the db (as a set).
        self.appRoutes = {}  # dict of all app routes, with note of if protected.  by blueprint: route: {protected,
        self.rootRole = rootRole # Name of the Role designated to function as root control.

        if path:
            self.path = path
        elif current_app.root_path:
            self.path = current_app.root_path
        else:
            self.path = os.path.dirname(sys.modules['__main__'].__file__)

        self.addDefaultPermissions()
        self.codeParse()
        self.dbParse()

        self.appRouteParse()
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
        """
        Parses declared Permissions and Roles in the app python code.
        :return:
        """
        tp = TemplateParser(path=self.path)
        pp = PyMain(path=self.path)

        tp.run()
        pp.run()
        self.templates = tp.output
        self.routesByFile = pp.output

        # add template information to routes, and add all declared permissions to usedPerms Set
        for template in self.templates:
            self.templates[template]['renders'] = {}
            for use in self.templates[template]:
                for perm in self.templates[template][use]['permissions']:
                    self.usedPerms.add(perm)
            for file in self.routesByFile:
                for bp in self.routesByFile[file]:
                    for route in self.routesByFile[file][bp]:
                        for perm in self.routesByFile[file][bp][route]['permissions']: # add route permissions to usedPerms set
                            self.usedPerms.add(perm)
                        for role in self.routesByFile[file][bp][route]['roles']: # add route permissions to usedPerms set
                            self.usedRoles.add(role)
                        if template in self.routesByFile[file][bp][route]['templates']:
                            self.routesByFile[file][bp][route]['templates'][template] = self.templates[template]
                            if bp not in self.templates[template]['renders']:
                                self.templates[template]['renders'][bp] = {}
                            self.templates[template]['renders'][bp][route]['line_number'] = self.routesByFile[file][bp][route]['line_number']
                            self.templates[template]['renders'][bp][route]['other_decorators'] = self.routesByFile[file][bp][route]['other_decorators']
                            self.templates[template]['renders'][bp][route]['permissions'] = self.routesByFile[file][bp][route]['permissions']
                            self.templates[template]['renders'][bp][route]['roles'] = self.routesByFile[file][bp][route]['roles']
                            self.templates[template]['renders'][bp][route]['file'] = file

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

    def dbParse(self):
        """
        Parses declared Permissions and Roles in the app database.
        :return:
        """
        self.roles = Role.query.all()
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
        self.users = User.query.all()
        dbPermNameList = []
        for perm in self.dbPerms:
            dbPermNameList.append(perm.name)
            if len(set(dbPermNameList)) != len(dbPermNameList):
                raise AssertionError('Permissions with duplicate values exist in Permission store.')
            self.dbPermNames = set(dbPermNameList)

    def appRouteParse(self):
        """
        Parses a dict of all routes in the app.
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

    def check_missing(self):
        self.missingPerms = self.usedPerms - self.dbPermNames
        self.unutilizedPerms = self.dbPermNames - self.usedPerms
        self.missingRoles = self.usedRoles - self.roleNames

    def role_parse(self):
        """
        add role based permissions to routesByBlueprint dict.
        :return:
        """

        for bp in self.routesByBlueprint:
            for route in self.routesByBlueprint[bp]:
                for roleName in self.routesByBlueprint[bp][route]['roles']:
                    if roleName in self.roleNames:
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

        print('Permission report:')
        print('- - - - - - - - - - - - - - - - - - - -')
        if self.missingPerms:
            print('!--Permissions used in app not found in Permission store--!')
            for perm in self.missingPerms:
                print(f'<{perm}> ,', end='')
            print('')
            print('------------------------------------')
        else:
            print('---All used Permissions declared---')
        print('')
        if self.unutilizedPerms:
            print('!--Unutilized Permissions found in Permission store--!')
            for perm in self.unutilizedPerms:
                print(f'<{perm}> ,', end='')
            print('')
            print('------------------------------------')
        else:
            print('---All declared Permissions used---')

        print('')
        print(f'Root Role (Role with all Permissions) specified as <{self.rootRole}>')
        root = Role.query.filter_by(name=self.rootRole).first()
        if not root:
            print(f'!--<{self.rootRole}> not found in Role store--!')
        else:
            if root.allPermissionsRoles[0] - self.usedPerms:
                print(f'!--<{self.rootRole}> missing used Permissions--!')
                for perm in root.allPermissionsRoles[0] - self.usedPerms:
                    print(f'<{perm}> ,', end='')
                print('')
                print('------------------------------------')
            else:
                print(f'---All used Permissions currently assigned to <{self.rootRole}>')
            print('')
            if root.allPermissionsRoles[0] - self.dbPermNames:
                print(f'!--<{self.rootRole}> missing declared db Permissions--!')
                for perm in root.allPermissionsRoles[0] - self.dbPermNames:
                    print(f'<{perm}> ,', end='')
                print('')
                print('------------------------------------')
            else:
                print(f'---All declared Permissions currently assigned to <{self.rootRole}>')
        print('')
        print('---Routes with undeclared Permissions---')

        for bp in self.routesByBlueprint:
            print('-  -  -  -  -  -  -')
            print(f'Blueprint: {bp}')
            for route in self.routesByBlueprint[bp]:
                if self.routesByBlueprint[bp][route]['permissions'] not in self.dbPermNames:
                    print(f'\t{route} in {self.routesByBlueprint[bp][route]["file"]}'
                          f'({self.routesByBlueprint[bp][route]["line_number"]}): '
                          f'{self.dbPermNames - set(self.routesByBlueprint[bp][route]["permissions"])}')
        print('---------------------------------------')
        print('')

        print('---Templates with undeclared Permissions---')


        for template in self.templates:
            templatePerms = []
            for usage in self.templates[template]:
                templatePerms.extend(self.templates[template][usage]['permissions'])
            if templatePerms not in self.dbPermNames:
                templateRoutes = []
                for bp in self.templates[template]['renders']:
                    for route in self.templates[template]['renders'][bp]:
                        templateRoutes.append(bp+"."+route)
                print(f'{template} rendered by {tRoute }')

        print('')
        print('---Unprotected Routes---')








        # root role status
        # unready routes (missing permission or role in db) also check if role has no permissions
        # WARN IF ROLES MISSING THAT PERMISSIONS REQUIRED WILL NOT BE COMPLETE
        # unprotected routes by blueprint
        # protected routes by blueprint


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


class PyMain:

    def __init__(self, path=None):
        self.output = {}
        self.pyFiles = []
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

                analyzer = PyAnalyzer()
                analyzer.visit(tree)
                if analyzer.routes:
                    self.output[os.path.relpath(file, self.path)] = analyzer.routes

    def printResults(self):
        pprint(self.output)

    def listDeclaredPerms(self):
        permList = []
        for file in self.output:
            for blueprint in file:
                for route in blueprint:
                    permList.extend(route['permissions'])
        return permList


class PyAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.routes = {}
        self.decorators = []

    def visit_FunctionDef(self, node):

        # Get route info
        if node.decorator_list:
            if isinstance(node.decorator_list[0], ast.Call):
                if isinstance(node.decorator_list[0].func, ast.Attribute):
                    if node.decorator_list[0].func.attr == 'route':
                        blueprint = node.decorator_list[0].func.value.id
                        permFunc = False
                        for dec in node.decorator_list[1:]:
                            if isinstance(dec, ast.Call):
                                if isinstance(dec.func, ast.Name):
                                    if dec.func.id == 'permission_required':
                                        permFunc = True
                                        break
                        if permFunc:
                            # Found a permission_required decorated route.

                            # if the blueprint hasn't been seen yet, save to dict
                            if blueprint not in self.routes.keys():
                                self.routes[blueprint] = {}

                            # Save the route endpoint
                            self.routes[blueprint][node.name] = {'url': node.decorator_list[0].args[0].s,
                                                                 'permissions': [], 'roles': [], 'line_number': node.lineno,
                                                                 'other_decorators': [], 'templates': {}}

                            # get the permission required info, and also other decorators present
                            for dec in node.decorator_list[1:]:
                                if isinstance(dec, ast.Call):
                                    if isinstance(dec.func, ast.Name):
                                        if dec.func.id == 'permission_required':
                                            for arg in dec.keywords:
                                                if arg.arg == "permissions":
                                                    for perm in arg.value.elts:
                                                        self.routes[blueprint][node.name]['permissions'].append(perm.s)
                                                elif arg.arg == "roles":
                                                    # ToDo finish roles tree walk
                                                    for perm in arg.value.elts:
                                                        self.routes[blueprint][node.name]['roles'].append(perm.s)
                                        else:
                                            self.routes[blueprint][node.name]['other_decorators'].append(dec.func.id)
                                    elif isinstance(dec.func, ast.Attribute):
                                        self.routes[blueprint][node.name]['other_decorators'].append(dec.func.attr)
                                elif isinstance(dec, ast.Name):
                                    self.routes[blueprint][node.name]['other_decorators'].append(dec.id)

                            # get template served by route:
                            for bodyNode in node.body:
                                if isinstance(bodyNode, ast.Return):
                                    if isinstance(bodyNode.value, ast.Call):
                                        if isinstance(bodyNode.value.func, ast.Name):
                                            if bodyNode.value.func.id == 'render_template':
                                                self.routes[blueprint][node.name]['templates'][bodyNode.value.args[0].s] = {}


        self.generic_visit(node)

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


