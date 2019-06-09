import os
import sys
import ast

from flask import current_app
from pprint import pprint
from jinja2 import Environment, FileSystemLoader, meta, visitor




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
            if node.test.name == "perm_check":
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
        if isinstance(node.func, ast.Name):
            if node.func.id == "blueprint_permission_required":
                pass
            if node.func.id == "permissionCheck":
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
