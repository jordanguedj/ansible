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
  project_id:
    description:
      - Your GCP project ID.
  permissions:
    description:
      - IAM permissions to configure with the IAM resource.
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
from ansible.module_utils.gcp import get_google_api_client, GCPUtils


USER_AGENT_PRODUCT = 'ansible-healthcheck'
USER_AGENT_VERSION = '0.0.1'


def _get_req_resource(client, resource_type):
    if resource_type == 'projects':
        return client.projects()


def create_role(client, project_id, title, description, permissions):
    try:
        resource_type = 'projects'
        projects = _get_req_resource(client, resource_type)
        body = {
            'roleId': ''.join(e for e in title if e.isalnum()),
            'role': {
                'description': description,
                'title': title,
                'includedPermissions': permissions
            }
        }
        args = {'parent': '{}/{}'.format(
            resource_type, project_id), 'body': body}
        req = projects.roles().create(**args)
        return_data = GCPUtils.execute_api_client_req(req, raise_404=False)
        return (True, return_data)
    except:
        raise


def main():
    module = AnsibleModule(
        argument_spec=dict(
            iam_type=dict(type='str'),
            title=dict(type='str'),
            description=dict(type='str'),
            project_id=dict(type='str'),
            permissions=dict(type='list'),
            state=dict(type='state'),
        ),
        mutually_exclusive=[
        ],
        required_one_of=[
            ['iam_type', 'title', 'project_id']
        ],
    )

    client, conn_params = get_google_api_client(
        module,
        'iam',
        user_agent_product=USER_AGENT_PRODUCT,
        user_agent_version=USER_AGENT_VERSION)

    params = {}

    params['iam_type'] = module.params.get('iam_type')
    params['title'] = module.params.get('title')
    params['description'] = module.params.get('description')
    params['project_id'] = module.params.get('project_id')
    params['permissions'] = module.params.get('permissions')
    params['state'] = module.params.get('state')
    params['changed'] = False
    json_output = {}

    if params['iam_type'] == 'role':
        client, conn_params = get_google_api_client(module, 'iam',
            user_agent_product=USER_AGENT_PRODUCT,
            user_agent_version=USER_AGENT_VERSION)
        changed, json_output = create_role(client, params['project_id'],
            params['title'], params['description'], params['permissions'])
    json_output['changed'] = changed
    module.exit_json(**json_output)


if __name__ == '__main__':
    main()
