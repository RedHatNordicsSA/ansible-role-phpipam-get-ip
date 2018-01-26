#!/usr/bin/python

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: phpipam_ip
short_description: Get free IP address from phpipam
description:
   - This module controls ip assignment in phpipam
author: Peter Gustafsson 
version_added: "0.1"
options:
   state:
      description:
         - "Specifies if a IP should be created or deleted."
      choices: ['present', 'absent']
      required: True
      default: null
   base_url:
      description:
         - "A string containing the base URL of the server.
           For example: I(https://phpipam.example.com/api)." 
      required: True
      default: null
   app_id:
      description:
         - "API App Id"
      required: True
      default: null
   username:
      description:
         - "The name of the user. For example: (admin)."
      required: True
      default: null
   password:
      description:
         - "The password of the user."
      required: True
      default: null
   ssl_verify:
      description:
         - "A boolean flag that indicates if the SSL certificate should be verified."
      required: True
      default: False
   subnet:
      description:
         - "Creates new address(first available) in subnet. 
           Subnet should be specified in CIDR format.
           For example: (192.168.0.0/24)."
      required: True
      default: null
   hostname:
      description:
         - "Register hostname with IP"
      required: False
      default: null
   ip_addr:
      description:
         - Deletes address.
      required: False
      default: null
notes:
   - Require phpipam version 1.3 
'''

EXAMPLES = '''
# Creates new address(first available) in subnet 192.168.0.0/24.
phpipam_ip: 
  base_url: "http://phpipam.example.com/api"
  app_id: "ansible"
  username: "admin"
  password: "secret"
  subnet: "192.168.0.0/24"
  hostname: "test.example.com"
  state: present
register: result
# Deletes IP reservation for IP 192.168.0.10.
phpipam_ip: 
  base_url: "http://phpipam.example.com/api"
  app_id: "ansible"
  username: "admin"
  password: "secret"
  ip_addr: "10.32.213.198"
  state: absent
'''
from ansible.module_utils.basic import *
import requests
import json
import logging, sys
logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)

def get_token(base_url, app_id, username, password, ssl_verify):
   # Performs a GET using the passed URL location and returns token
   url = "{}{}{}{}" . format(base_url, '/', app_id, '/user/')
   try:
      r = requests.post(url, auth=(username, password), verify=ssl_verify) 
      result = r.json()
      r.raise_for_status()
   except requests.exceptions.RequestException as err:
      return False, result
   token =  result['data']['token']
   headers = {} 
   headers['token'] = token 
   return True, headers

def get_ip_id(base_url, app_id, ip_addr, headers, ssl_verify):
   url = "{}{}{}{}{}{}" . format(base_url, '/', app_id, '/addresses/search/', ip_addr, '/')
   try:
      r = requests.get(url, headers=headers, verify=ssl_verify)
      result = r.json()
      r.raise_for_status()
   except requests.exceptions.RequestException as err:
      return False, result
   try:
      subnet_id = result['data'][0]['id']
   except:
      return False, result['message']
   return True, subnet_id

def get_subnet_id(base_url, app_id, subnet, headers, ssl_verify):
   url = "{}{}{}{}{}{}" . format(base_url, '/', app_id, '/subnets/cidr/', subnet, '/')
   try:
      r = requests.get(url, headers=headers, verify=ssl_verify)
      result = r.json()
      r.raise_for_status()
   except requests.exceptions.RequestException as err:
      return False, result
   try:
      subnet_id = result['data'][0]['id']
   except:
      return False, result['message']
   return True, subnet_id

def get_gw_and_dns(base_url, app_id, subnet_id, headers, ssl_verify):
   ip_info = {}
   url = "{}{}{}{}{}{}" . format(base_url, '/', app_id, '/subnets/', subnet_id, '/')
   try:
      r = requests.get(url, headers=headers, verify=ssl_verify)
      result = r.json()
      r.raise_for_status()
   except requests.exceptions.RequestException as err:
      return False, result
   try:
      ip_info['gateway'] = result['data']['gateway']['ip_addr']
   except:
      return False, "Gateway is not defined for this subnet"
   try:
      ip_info['nameservers'] = result['data']['nameservers']['namesrv1'].split(";")
#      for i in range(0, len(nameserver_list)):
#         ns = "nameserver{}".format(i+1)
#         ip_info[ns] = nameserver_list[i]
#      ip_info['nameservers'] = {}
#      nameserver_list = result['data']['nameservers']['namesrv1'].split(";")
#      for i in range(0, len(nameserver_list)):
#         ns = "nameserver{}".format(i+1)
#         ip_info['nameservers'][ns] = nameserver_list[i]
   except:
      return False, "Nameserver is not defined for this subnet"
   try:
      ip_info['netmask'] = result['data']['calculation']['Subnet netmask']
   except:
      return False, "Netmask is not defined for this subnet"
   return True, ip_info

def get_first_free_ip(base_url, app_id, subnet_id, hostname, headers, ssl_verify):
   url = "{}{}{}{}{}{}" . format(base_url, '/', app_id, '/addresses/first_free/', subnet_id, '/')
   payload = {'hostname': hostname}
   try:
      r = requests.post(url, headers=headers, data=payload, verify=ssl_verify)
      result = r.json()
      r.raise_for_status()
   except requests.exceptions.RequestException as err:
      return False, result
   try:
      ip = result['data']
   except:
      return False, result['message']
   return True, ip

def delete_ip(base_url, app_id, ip_id, headers, ssl_verify):
   url = "{}{}{}{}{}{}" . format(base_url, '/', app_id, '/addresses/', ip_id, '/')
   try:
      r = requests.delete(url, headers=headers, verify=ssl_verify)
      result = r.json()
      r.raise_for_status()
   except requests.exceptions.RequestException as err:
      return False, result
   return True, result

def get_free_ip(data):
   # Get token 
   success, response = get_token(data['base_url'],data['app_id'],data['username'],data['password'],data['ssl_verify'])
   if not success:
      return True, False, response
   headers = response

   del data['state']
   del data['username']
   del data['password']

   # Get subnet id, Subnet ID will be used in the remaining api queries.
   success, response = get_subnet_id(data['base_url'],data['app_id'],data['subnet'],headers,data['ssl_verify']) 
   if not success:
      return True, False, response
   subnet_id = response

   del data['subnet']

   # Get gateway, DNS and netmask
   success, ip_info = get_gw_and_dns(data['base_url'],data['app_id'],subnet_id,headers,data['ssl_verify']) 
   if not success:
      return True, False, ip_info

   # Get ip
   success, ip_result = get_first_free_ip(data['base_url'],data['app_id'],subnet_id,data['hostname'],headers,data['ssl_verify'])
   if not success:
      return True, False, ip_result
   ip_info['ip_addr'] =  ip_result
   
   # Exit function
   return False, True, ip_info


def release_ip(data=None):
   # Get token
   success, response = get_token(data['base_url'],data['app_id'],data['username'],data['password'],data['ssl_verify'])
   if not success:
      return True, False, response
   headers = response

   # Get ip id, Ip ID will be used in the remaining api queries.
   success, response = get_ip_id(data['base_url'], data['app_id'], data['ip_addr'], headers, data['ssl_verify'])
   if not success:
      return True, False, response
   ip_id = response

   # Release the IP
   success, response = delete_ip(data['base_url'], data['app_id'], ip_id, headers, data['ssl_verify'])
   if not success:
      return True, False, response

   # exit function
   return False, True, response 

def main():
   module = AnsibleModule(
      argument_spec=dict(
         base_url=dict(required=True, type="str"),
         app_id=dict(required=True, type="str"),
         username=dict(required=True, type="str"),
         password=dict(required=True, type="str", default=None, no_log=True),
         ssl_verify=dict(default=False, type="bool"),
         subnet=dict(type="str"),
         ip_addr=dict(type="str"),
         hostname=dict(type="str"),
         state=dict(
            required=True,
            choices=['present', 'absent']),
      ),
      supports_check_mode=True,
      required_if=(
         ['state', 'present', ['subnet']],
         ['state', 'absent', ['ip_addr']]
      )
   )
 
   choice_map = {
      "present": get_free_ip,
      "absent": release_ip,
   }
   
   is_error, has_changed, result = choice_map.get(
      module.params['state'])(module.params)

   if not is_error:
      module.exit_json(changed=has_changed, meta=result)
   else:
      module.fail_json(msg="Error", meta=result)


if __name__ == '__main__':  
   main()
