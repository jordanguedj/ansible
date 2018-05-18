#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    AUTO GENERATED CODE     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file at
#     https://www.github.com/GoogleCloudPlatform/magic-modules
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function
__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ["preview"],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_iam_role
description:
    - A role in the Identity and Access Management API.
short_description: Creates a GCP Role
version_added: 2.6
author: Jordan Guedj (@jordanguedj) <guedj.jordan@gmail.com>
requirements:
    - python >= 2.6
    - requests >= 2.18.4
    - google-auth >= 1.3.0
options:
    state:
        description:
            - Whether the given object should exist in GCP
        choices: ['present', 'absent']
        default: 'present'
    permissions:
        description:
            - Comma-separated IAM permissions to configure with the role.
        required: false
    project_id:
        description:
            - Id of the project that owns the service account.
        required: false
    title:
        description:
            - Role's title.
        required: false
    name:
        description:
            - Role's name.
        required: false
    description:
        description:
            - Role's description.
        required: false
extends_documentation_fragment: gcp
'''

EXAMPLES = '''
- name: create a role
  gcp_iam_role:
      permissions: ['pubsub.subscriptions.get', 'pubsub.subscriptions.consume']
      title: "Ansible IAM Role Module"
      name: "TestAnsibleIAMRoleModule"
      description: "This role has been generated by Ansible IAM Role Module."
      project: testProject
      auth_kind: service_account
      service_account_file: /tmp/auth.pem
      scopes:
        - https://www.googleapis.com/auth/iam
      state: present
'''

RETURN = '''
    permissions:
        description:
            - Comma-separated IAM permissions to configure with the role.
        returned: success
        type: list
    project_id:
        description:
            - Id of the project that owns the service account.
        returned: success
        type: str
    title:
        description:
            - Role's title.
        returned: success
        type: str
    name:
        description:
            - Role's name.
        returned: success
        type: str
    description:
        description:
            - Role's description.
        returned: success
        type: str
'''

################################################################################
# Imports
################################################################################

from ansible.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest, replace_resource_dict
import json

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present', 'absent'], type='str'),
            permissions=dict(type='list', elements='str'),
            project_id=dict(type='str'),
            title=dict(type='str'),
            name=dict(type='str'),
            description=dict(type='str')
        )
    )

    state = module.params['state']

    fetch = fetch_resource(module, self_link(module))
    changed = False

    if fetch:
        if state == 'present':
            if is_different(module, fetch):
                fetch = update(module, self_link(module))
                changed = True
        else:
            delete(module, self_link(module))
            fetch = {}
            changed = True
    else:
        if state == 'present':
            fetch = create(module, collection(module))
            changed = True
        else:
            fetch = {}

    fetch.update({'changed': changed})

    module.exit_json(**fetch)


def create(module, link):
    auth = GcpSession(module, 'iam')
    return return_if_object(module, auth.post(link, resource_to_request(module)))


def update(module, link):
    auth = GcpSession(module, 'iam')
    return return_if_object(module, auth.put(link, resource_to_request(module)))


def delete(module, link):
    auth = GcpSession(module, 'iam')
    return return_if_object(module, auth.delete(link))


def resource_to_request(module):
    request = {
        u'permissions': module.params.get('permissions'),
        u'projectId': module.params.get('project_id'),
        u'title': module.params.get('title'),
        u'name': module.params.get('name'),
        u'description': module.params.get('description')
    }
    request = encode_request(request, module)
    return_vals = {}
    for k, v in request.items():
        if v:
            return_vals[k] = v

    return return_vals


def fetch_resource(module, link):
    auth = GcpSession(module, 'iam')
    return return_if_object(module, auth.get(link))


def self_link(module):
    return "https://iam.googleapis.com/v1/projects/{project}/roles/{name}".format(**module.params)


def collection(module):
    return "https://iam.googleapis.com/v1/projects/{project}/roles".format(**module.params)


def return_if_object(module, response):
    # If not found, return nothing.
    if response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    result = decode_response(result, module)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


def is_different(module, response):
    request = resource_to_request(module)
    response = response_to_hash(module, response)
    request = decode_response(request, module)

    # Remove all output-only from response.
    response_vals = {}
    for k, v in response.items():
        if k in request:
            response_vals[k] = v

    request_vals = {}
    for k, v in request.items():
        if k in response:
            request_vals[k] = v

    return GcpRequest(request_vals) != GcpRequest(response_vals)


# Remove unnecessary properties from the response.
# This is for doing comparisons with Ansible's current parameters.
def response_to_hash(module, response):
    return {
        u'permissions': response.get(u'permissions'),
        u'projectId': response.get(u'projectId'),
        u'title': response.get(u'title'),
        u'name': response.get(u'name'),
        u'description': response.get(u'description')
    }


# Format the request to match the expected input by the API
def encode_request(request, module):
    return {
        'roleId': module.params['name'],
        'role': {
            'description': module.params['description'],
            'title': module.params['title'],
            'includedPermissions': module.params['permissions']
        }
    }

def decode_response(response, module):
    return response

if __name__ == '__main__':
    main()
