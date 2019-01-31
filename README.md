ansible-role-phpipam-get-ip
===========================

Handles reserving and freeing of IP address for a server using
[phpIPAM](https://phpipam.net/) IP address manager.

Requirements
------------

phpIPAM server is needed.

Role Variables
--------------

There is list of variables in defaults/main.yml which can be overridden in
vault or in Tower. You may need to modify them to use this role.

Dependencies
------------

No dependencies.

Example Playbook
----------------

  - include_role:
      name: ansible-role-phpipam-get-ip
    vars:
      phpipam_hostname: "{{ short_hostname + '.' + domain }}"


License
-------

BSD

Author Information
------------------

Peter Gustafsson, pgustafs@redhat.com
[Red Hat](https://redhatnordicssa.github.io/)
