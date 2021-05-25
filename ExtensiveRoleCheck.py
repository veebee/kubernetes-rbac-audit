import json, yaml
import pathlib
import argparse
import logging
from colorama import init, Fore, Back, Style

def get_argument_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--clusterRole', type=str, required=False, help='ClusterRoles file, either JSON or YAML')
    parser.add_argument('--role', type=str, required=False, help='roles JSON file, either JSON or YAML')
    parser.add_argument('--rolebindings', type=str, required=False, help='RoleBindings JSON file, either JSON or YAML')
    parser.add_argument('--clusterolebindings', type=str, required=False, help='ClusterRoleBindings JSON file, either JSON or YAML')
    return parser.parse_args()

def isJsonFile(path):
    extension = path.suffix
    if (extension.lower() == ".json"):
        return True

    return False

def isYamlFile(path):
    extension = path.suffix
    if (extension.lower() == ".yaml" or extension.lower() == ".yml"):
        return True

    return False

# Read data from input files
def open_file(file_path):
    path = pathlib.Path(file_path)
    if (isJsonFile(path)):
        return open_json_file(path)
    elif (isYamlFile(path)):
        return open_yaml_file(path)
    else:
        return

# Read data from JSON files
def open_json_file(file_path):
    with open(file_path) as f:
        return json.load(f)

# Read data from YAML files
def open_yaml_file(file_path):
    with open(file_path) as f:
        return yaml.safe_load(f)

class ExtensiveRolesChecker(object):
    def __init__(self, role_file, role_kind):
        init()
        self._role = logging.getLogger(role_kind)
        self._role_handler = logging.StreamHandler()
        self._role_format = logging.Formatter(f'{Fore.YELLOW}[!][%(name)s]{Fore.WHITE}\u2192 %(message)s')
        self._role_handler.setFormatter(self._role_format)
        self._role.addHandler(self._role_handler)
        self._role_file = role_file
        self._results = {}
        self._generate()

    @property
    def results(self):
        return self._results

    def add_result(self, name, value):
        if not name:
            return
        if not (name in self._results.keys()):
            self._results[name] = [value]
        else:
            self._results[name].append(value)

    def _retrieveRules(self, role_name, rules):
        for rule in rules:
            if not rule.get('resources', None):
                continue
            self.get_read_secrets(rule, role_name)
            self.clusteradmin_role(rule, role_name)
            self.any_resources(rule, role_name)
            self.any_verb(rule, role_name)
            self.high_risk_roles(rule, role_name)
            self.role_and_roleBindings(rule, role_name)
            self.create_pods(rule, role_name)
            self.pods_exec(rule, role_name)
            self.pods_attach(rule, role_name)

    def _generateFromJson(self):
        for entity in self._role_file['items']:
            role_name = entity['metadata']['name']
            self._retrieveRules(role_name, entity['rules'])

    def _generateFromYaml(self):
        role_name = self._role_file['metadata']['name']
        self._retrieveRules(role_name, self._role_file['rules'])

    def _generate(self):
        if ('items' in self._role_file):
            return self._generateFromJson()
        else:
            return self._generateFromYaml()

    #Read cluster secrets:
    def get_read_secrets(self, rule, role_name):
        verbs = ['*','get','list']
        if ('secrets' in rule['resources'] and any([sign for sign in verbs if sign in rule['verbs']])):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to list secrets!')
                self.add_result(filtered_name, 'Has permission to list secrets!')

    #Any Any roles
    def clusteradmin_role(self, rule, role_name):
        if ('*' in rule['resources'] and '*' in rule['verbs']):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has Admin-Cluster permission!')
                self.add_result(filtered_name, 'Has Admin-Cluster permission!')

    #get ANY verbs:
    def any_verb(self, rule, role_name):
        resources = ['secrets',
                    'pods',
                    'deployments',
                    'daemonsets',
                    'statefulsets',
                    'replicationcontrollers',
                    'replicasets',
                    'cronjobs',
                    'jobs',
                    'roles',
                    'clusterroles',
                    'rolebindings',
                    'clusterrolebindings',
                    'users',
                    'groups']
        found_sign = [sign for sign in resources if sign in rule['resources']]
        if not found_sign:
            return
        if '*' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to access {found_sign[0]} with any verb!')
                self.add_result(filtered_name, f'Has permission to access {found_sign[0]} with any verb!')

    def any_resources(self, rule, role_name):
        verbs = ['delete','deletecollection', 'create','list' , 'get' , 'impersonate']
        found_sign = [sign for sign in verbs if sign in rule['verbs']]
        if not found_sign:
            return
        if ('*' in rule['resources']):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to use {found_sign[0]} on any resource!')
                self.add_result(filtered_name, f'Has permission to use {found_sign[0]} on any resource')

    def high_risk_roles(self, rule, role_name):
        verb_actions = ['create','update']
        resources_attributes = ['deployments','daemonsets','statefulsets','replicationcontrollers','replicasets','jobs','cronjobs']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not (found_attribute):
            return
        found_actions = [action for action in verb_actions if action in rule['verbs']]
        if not (found_actions):
            return
        filtered_name = self.get_non_default_name(role_name)
        if filtered_name:
            self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to {found_actions[0]} {found_attribute[0]}!')
            self.add_result(filtered_name, f'Has permission to {found_actions[0]} {found_attribute[0]}!')

    def role_and_roleBindings(self, rule, role_name):
        resources_attributes = ['rolebindings','roles','clusterrolebindings']
        found_attribute = [attribute for attribute in resources_attributes if attribute in rule['resources']]
        if not found_attribute:
            return
        if ('create' in rule['verbs']):
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to create {found_attribute[0]}!')
                self.add_result(filtered_name, f'Has permission to create {found_attribute[0]}!')


    def create_pods(self, rule, role_name):
        if 'pods' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}'+ f'{Fore.RED} Has permission to create pods!')
                self.add_result(filtered_name, 'Has permission to create pods!')

    def pods_exec(self, rule, role_name):
        if 'pods/exec' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to use pod exec!')
                self.add_result(filtered_name, 'Has permission to use pod exec!')

    def pods_attach(self, rule, role_name):
        if 'pods/attach' in rule['resources'] and 'create' in rule['verbs']:
            filtered_name = self.get_non_default_name(role_name)
            if filtered_name:
                self._role.warning(f'{Fore.GREEN}{filtered_name}' + f'{Fore.RED} Has permission to attach pods!')
                self.add_result(filtered_name, 'Has permission to attach pods!')

    @staticmethod
    def get_non_default_name(name):
        if not ((name[:7] == 'system:') or (name == 'edit') or (name == 'admin') or (name == 'cluster-admin') or (name == 'aws-node') or (name[:11] == 'kubernetes-')):
            return name


class roleBindingChecker(object):
    def __init__(self, role_file, extensive_roles, bind_kind):
        self._role_file = role_file
        self._extensive_roles = extensive_roles
        self._bind_kind = bind_kind
        self._results = []
        self.bindsCheck()

    def bindsCheck(self):
        _rolebiding_found = []
        for entity in self._role_file['items']:
            _role_name = entity['metadata']['name']
            _rol_ref = entity['roleRef']['name']
            if not entity.get('subjects', None):
                continue
            if _rol_ref in self._extensive_roles:
                _rolebiding_found.append(_rol_ref)
                for sub in entity['subjects']:
                    if not sub.get('name', None):
                        continue
                    self.print_rolebinding_results(sub, _role_name, self._bind_kind)
        return _rolebiding_found

    def print_rolebinding_results(self, sub, role_name, bind_kind):
        if sub['kind'] == 'ServiceAccount':
            print(f'{Fore.YELLOW}[!][{bind_kind}]{Fore.WHITE}\u2192 ' + f'{Fore.GREEN}{role_name}{Fore.RED} is binded to {sub["name"]} ServiceAccount.')
        else:
            print(f'{Fore.YELLOW}[!][{bind_kind}]{Fore.WHITE}\u2192 ' + f'{Fore.GREEN}{role_name}{Fore.RED} is binded to the {sub["kind"]}: {sub["name"]}!')



if __name__ == '__main__':
    args = get_argument_parser()

    if args.clusterRole:
        print('\n[*] Started enumerating risky ClusterRoles:')
        role_kind = 'ClusterRole'

        if (pathlib.Path(args.clusterRole).is_dir()):
            for file in pathlib.Path(args.clusterRole).iterdir():
                if (isJsonFile(file) or isYamlFile(file)):
                    clusterRole_file = open_file(args.clusterRole)
                    extensiveClusterRolesChecker = ExtensiveRolesChecker(clusterRole_file, role_kind)
                    extensive_ClusterRoles = [result for result in extensiveClusterRolesChecker.results]
        else:
            clusterRole_file = open_file(args.clusterRole)
            extensiveClusterRolesChecker = ExtensiveRolesChecker(clusterRole_file, role_kind)
            extensive_ClusterRoles = [result for result in extensiveClusterRolesChecker.results]

    if args.role:
        print(f'{Fore.WHITE}[*] Started enumerating risky Roles:')
        role_kind = 'Role'

        if (pathlib.Path(args.role).is_dir()):
            for file in pathlib.Path(args.role).iterdir():
                if (isJsonFile(file) or isYamlFile(file)):
                    role_file = open_file(args.role)
                    extensiveRolesChecker = ExtensiveRolesChecker(role_file, role_kind)
                    extensive_roles = [result for result in extensiveRolesChecker.results if result not in extensive_ClusterRoles]
                    extensive_roles = extensive_roles + extensive_ClusterRoles
        else:
            Role_file = open_file(args.role)
            extensiveRolesChecker = ExtensiveRolesChecker(Role_file, role_kind)
            extensive_roles = [result for result in extensiveRolesChecker.results if result not in extensive_ClusterRoles]
            extensive_roles = extensive_roles + extensive_ClusterRoles

    if args.clusterolebindings:
        print(f'{Fore.WHITE}[*] Started enumerating risky ClusterRoleBinding:')
        bind_kind = 'ClusterRoleBinding'

        if (pathlib.Path(args.clusterolebindings).is_dir()):
            for file in pathlib.Path(args.clusterolebindings).iterdir():
                if (isJsonFile((file) or isYamlFile(file))):
                    clusterRoleBinding_file = open_file(args.clusterolebindings)
                    extensive_clusteRoleBindings = roleBindingChecker(clusterRoleBinding_file, extensive_roles, bind_kind)

        else:
            clusterRoleBinding_file = open_file(args.clusterolebindings)
            extensive_clusteRoleBindings = roleBindingChecker(clusterRoleBinding_file, extensive_roles, bind_kind)

    if args.rolebindings:
        print(f'{Fore.WHITE}[*] Started enumerating risky RoleRoleBindings:')
        bind_kind = 'RoleBinding'

        if (pathlib.Path(args.rolebindings).is_dir()):
            for file in pathlib.Path(args.rolebindings).iterdir():
                RoleBinding_file = open_file(args.rolebindings)
                extensive_RoleBindings = roleBindingChecker(RoleBinding_file, extensive_roles, bind_kind)

        else:
            RoleBinding_file = open_file(args.rolebindings)
            extensive_RoleBindings = roleBindingChecker(RoleBinding_file, extensive_roles, bind_kind)
