#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: gcp_iam
version_added: "2.6"
short_description: Create, Update or Destroy a Healthcheck.
description:
    - Manages identity and access control for Google Cloud Platform resources,
      including the creation of service accounts, which you can use to
      authenticate to Google and make API calls.
    - Visit
      U(https://cloud.google.com/iam/docs/)
      for an overview of Google Cloud Identity and Access Management.
    - See
      U(https://cloud.google.com/iam/reference/rest/) for
      API details.
requirements:
  - "python >= 2.6"
  - "google-api-python-client >= 1.6.6"
  - "google-auth >= 1.4.1"
  - "google-auth-httplib2 >= 0.0.3"
author:
  - "Jordan Guedj (@jordanguedj) <guedj.jordan@gmail.com>"
options:
  iam_type:
    description:
       - Type of IAM resource.
  title:
    description:
       - Title of IAM resource.
  description:
    description:
       - Description of IAM resource.
  email:
    description:
       - Email of IAM resource.
  key_type:
    description:
       - The type of service account key to generate. It will generate credentials files by default.
    choices: ["credentials_file", "pkcs12_file"]
  key_algorithm:
    description:
       - The key algorithm. It will generate 2048-bit RSA keys by default.
    choices: ["rsa_1024", "rsa_2048"]
  project_id:
    description:
      - Your GCP project ID.
  organization_id:
    description:
      - Your GCP organization ID.
  permissions:
    description:
      - IAM permissions to configure with the IAM resource.
  role:
    description:
      - The role name to apply.
  members:
    description:
      - The members to bind with the role.
  state:
    description: State of the IAM resource.
    required: true
    choices: ["present", "absent"]
'''

EXAMPLES = '''
- name: Create role
  gcp_iam:
    iam_type: role
    title: "My role"
    description: "This is a role."
    project_id: "{{ project_id }}"
    permissions: ["pubsub.subscriptions.consume"]
    state: present
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.gcp import check_params, get_google_api_client, GCPUtils


USER_AGENT_PRODUCT = 'ansible-healthcheck'
USER_AGENT_VERSION = '0.0.1'


def _get_req_resource(client, resource_type):
    if resource_type == 'projects':
        return client.projects()
    if resource_type == 'organizations':
        return client.organizations()


def _validate_params(params):
    fields = [
        {'name': 'iam_type', 'type': str, 'required': True, 'values': [
            'role', 'service_account', 'service_account_key', 'policy']},
        {'name': 'title', 'type': str},
        {'name': 'name', 'type': str},
        {'name': 'description', 'type': str},
        {'name': 'email', 'type': str},
        {'name': 'key_type', 'type': str, 'values': [
            'credentials_file', 'pkcs12_file']},
        {'name': 'key_algorithm', 'type': str, 'values': [
            'rsa_1024', 'rsa_2048']},
        {'name': 'project_id', 'type': str},
        {'name': 'organization_id', 'type': str},
        {'name': 'permissions', 'type': list},
        {'name': 'role', 'type': str},
        {'name': 'members', 'type': list},
    ]
    try:
        check_params(params, fields)
        if params['iam_type'] == 'service_account' and 'organization_id' in params:
            raise ValueError("You cannot create service accounts for an organization.")
        if params['iam_type'] == 'service_account_key':
            if 'organization_id' in params:
                raise ValueError("You cannot create service account keys for an organization.")
            if not 'email' in params:
                raise ValueError("You cannot create service account keys without an email.")
    except:
        raise


def create_service_account_key(client, project_id, name, key_type=None, key_algorithm=None):
    try:
        resource_type = 'projects'
        key_types = {
            'credentials_file': 'TYPE_GOOGLE_CREDENTIALS_FILE',
            'pkcs12_file': 'TYPE_PKCS12_FILE',
            'default': 'TYPE_GOOGLE_CREDENTIALS_FILE'
        }
        key_algorithms = {
            'rsa_1024': 'KEY_ALG_RSA_1024',
            'rsa_2048': 'KEY_ALG_RSA_2048',
            'default': 'KEY_ALG_RSA_2048'
        }
        projects = _get_req_resource(client, resource_type)

        body = {
            "privateKeyType": key_types[key_type] if key_type else key_types['default'],
            "keyAlgorithm": key_algorithms[key_algorithm] if key_algorithm else key_algorithms['default']
        }
        args = {'name': '{}/{}/serviceAccounts/{}'.format(
            resource_type, project_id, name.lower().replace(' ', '-')), 'body': body}
        req = projects.serviceAccounts().keys().create(**args)
        return_data = GCPUtils.execute_api_client_req(req, raise_404=False)
        return (True, return_data)
    except:
        raise


def create_service_account(client, project_id, name):
    try:
        resource_type = 'projects'
        projects = _get_req_resource(client, resource_type)
        body = {
            "accountId": name.lower().replace(' ', '-'),
            "serviceAccount": {
                'displayName': name
            }
        }
        args = {'name': '{}/{}'.format(resource_type, project_id), 'body': body}
        req = projects.serviceAccounts().create(**args)
        return_data = GCPUtils.execute_api_client_req(req, raise_404=False)
        return (True, return_data)
    except:
        raise


def create_role(client, resource_type, resource_id, title, description, permissions):
    try:
        resources = _get_req_resource(client, resource_type)
        body = {
            'roleId': ''.join(e for e in title if e.isalnum()),
            'role': {
                'description': description,
                'title': title,
                'includedPermissions': permissions
            }
        }
        args = {'parent': '{}/{}'.format(
            resource_type, resource_id), 'body': body}
        req = resources.roles().create(**args)
        return_data = GCPUtils.execute_api_client_req(req, raise_404=False)
        return (True, return_data)
    except:
        raise


def update_policy(client, resource_type, resource_id, role, members):
    try:
        resources = _get_req_resource(client, resource_type)
        args = {'resource': resource_id, 'body': {}}
        req = resources.getIamPolicy(**args)
        policy_data = GCPUtils.execute_api_client_req(req, raise_404=False)
        body = {
            "policy": policy_data
        }
        body['policy']['bindings'].append({
            'members': members,
            'role': 'roles/{}'.format(role)
        })
        req = resources.setIamPolicy(resource=resource_id, body=body)
        return_data = GCPUtils.execute_api_client_req(req, raise_404=False)
        return (True, return_data)
    except:
        raise


def main():
    module = AnsibleModule(
        argument_spec=dict(
            iam_type=dict(type='str'),
            title=dict(type='str'),
            name=dict(type='str'),
            description=dict(type='str'),
            email=dict(type='str'),
            key_type=dict(type='str'),
            key_algorithm=dict(type='str'),
            project_id=dict(type='str'),
            organization_id=dict(type='str'),
            permissions=dict(type='list'),
            role=dict(type='str'),
            members=dict(type='list'),
        ),
        mutually_exclusive=[
            ['project_id', 'organization_id'],
            ['members', 'permissions']
        ],
        required_one_of=[
            ['iam_type'],
            ['project_id', 'organization_id']
        ],
    )

    client, conn_params = get_google_api_client(
        module,
        'iam',
        user_agent_product=USER_AGENT_PRODUCT,
        user_agent_version=USER_AGENT_VERSION)

    params = {}
    params['iam_type'] = module.params.get('iam_type')
    if module.params.get('title'):
        params['title'] = module.params.get('title')
    if module.params.get('name'):
        params['name'] = module.params.get('name')
    if module.params.get('description'):
        params['description'] = module.params.get('description')
    if module.params.get('email'):
        params['email'] = module.params.get('email')
    if module.params.get('key_type'):
        params['key_type'] = module.params.get('key_type')
    if module.params.get('key_algorithm'):
        params['key_algorithm'] = module.params.get('key_algorithm')
    if module.params.get('project_id'):
        params['project_id'] = module.params.get('project_id')
    if module.params.get('organization_id'):
        params['organization_id'] = module.params.get('organization_id')
    if module.params.get('permissions'):
        params['permissions'] = module.params.get('permissions')
    if module.params.get('role'):
        params['role'] = module.params.get('role')
    if module.params.get('members'):
        params['members'] = module.params.get('members')
    params['changed'] = False
    json_output = {}

    try:
        _validate_params(params)
    except Exception as e:
        module.fail_json(msg=e, changed=False)

    api = 'iam'
    if params['iam_type'] == 'policy':
        api = 'cloudresourcemanager'
    client, conn_params = get_google_api_client(module, api,
        user_agent_product=USER_AGENT_PRODUCT,
        user_agent_version=USER_AGENT_VERSION)
    if params['iam_type'] == 'role' or params['iam_type'] == 'policy':
        if 'project_id' in params:
            resource_type = 'projects'
            resource_id = 'project_id'
        if 'organization_id' in params:
            resource_type = 'organizations'
            resource_id = 'organization_id'
        if 'permissions' in params:
            changed, json_output = create_role(client, resource_type,
                params[resource_id], params['title'],
                params['description'], params['permissions'])
        if params['iam_type'] == 'policy':
            changed, json_output = update_policy(client, resource_type,
                params[resource_id], params['role'], params['members'])
    if params['iam_type'] == 'service_account':
        changed, json_output = create_service_account(
            client, params['project_id'], params['name'])
    if params['iam_type'] == 'service_account_key':
        key_type = params['key_type'] if 'key_type' in params else None
        key_algorithm = params['key_algorithm'] if 'key_algorithm' in params else None
        changed, json_output = create_service_account_key(
            client, params['project_id'], params['email'],
            key_type, key_algorithm)

    json_output['changed'] = changed
    module.exit_json(**json_output)


if __name__ == '__main__':
    main()
