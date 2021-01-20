LogStream for NGINX Controller App Sec
=======================================================================
.. contents:: Table of Contents

Introduction
==================================================
Use Case
###############

LogStream forwards http security event logs - received from NGINX Controller App Sec - to remote syslog servers (log collector, SIEM)

Demo
###############

ToDo

Security consideration
#########################
No logs are stored. LogStream receives logs and then PUSH them directly to remote log collector servers.

Pre requisites
==================================================

Virtualenv
***************************
- Create a virtualenv following `this guide <https://docs.ansible.com/ansible-tower/latest/html/upgrade-migration-guide/virtualenv.html>`_
- In virtualenv, as a prerequisite for Azure collection, install Azure SDK following `this guide <https://github.com/ansible-collections/azure>`_

Credential
***************************
- Create a Service Principal on Azure following `this guide <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>`_
- Create a Microsoft Azure Resource Manager following `this guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html#microsoft-azure-resource-manager>`_
- Create Credentials ``cred_NGINX`` to manage access to NGINX instances following `this guide <https://docs.ansible.com/ansible-tower/latest/html/userguide/credentials.html#machine>`_

=====================================================   =============================================   =============================================   =============================================   =============================================
REDENTIAL TYPE                                          USERNAME                                        SSH PRIVATE KEY                                 SIGNED SSH CERTIFICATE                          PRIVILEGE ESCALATION METHOD
=====================================================   =============================================   =============================================   =============================================   =============================================
``Machine``                                             ``my_VM_admin_user``                            ``my_VM_admin_user_key``                        ``my_VM_admin_user_CRT``                        ``sudo``
=====================================================   =============================================   =============================================   =============================================   =============================================

Role
***************************
Clone roles from `NGINX Controller collection <https://github.com/nginxinc/ansible-collection-nginx_controller>`_ in `/etc/ansible/roles/`

- nginxinc.nginx_controller_generate_token
- nginxinc.nginx_controller_integration
- nginxinc.nginx_controller_forwarder

Rename generated directory of these roles as listed above

Ansible role structure
######################
- Deployment is based on ``workflow template``. Example: ``workflow template`` = ``wf-create_create_edge_security_inbound``
- ``workflow template`` includes multiple ``job template``. Example: ``job template`` = ``poc-azure_create_hub_edge_security_inbound``
- ``job template`` have an associated ``playbook``. Example: ``playbook`` = ``playbooks/poc-azure.yaml``
- ``playbook`` launch a ``play`` in a ``role``. Example: ``role`` = ``poc-azure``

.. code:: yaml

    - hosts: localhost
      gather_facts: no
      roles:
        - role: poc-azure

- ``play`` is an ``extra variable`` named ``activity`` and set in each ``job template``. Example: ``create_hub_edge_security_inbound``
- The specified ``play`` (or ``activity``) is launched by the ``main.yaml`` task located in the role ``tasks/main.yaml``

.. code:: yaml

    - name: Run specified activity
      include_tasks: "{{ activity }}.yaml"
      when: activity is defined

- The specified ``play`` contains ``tasks`` to execute. Example: play=``create_hub_edge_security_inbound.yaml``

Installation
==================================================
Remote Syslog
#################
-  `Optimize the Network Kernel Parameters <https://docs.fluentd.org/installation/before-install#optimize-the-network-kernel-parameters>`_

.. code:: bash

    vi /etc/sysctl.conf
        net.core.somaxconn = 1024
        net.core.netdev_max_backlog = 5000
        net.core.rmem_max = 16777216
        net.core.wmem_max = 16777216
        net.ipv4.tcp_wmem = 4096 12582912 16777216
        net.ipv4.tcp_rmem = 4096 12582912 16777216
        net.ipv4.tcp_max_syn_backlog = 8096
        net.ipv4.tcp_slow_start_after_idle = 0
        net.ipv4.tcp_tw_reuse = 1
        net.ipv4.ip_local_port_range = 10240 65535
    sysctl -p

- Install `Fluentd <https://docs.fluentd.org/installation/install-by-rpm>`_

.. code:: bash

    curl -L https://toolbelt.treasuredata.com/sh/install-redhat-td-agent4.sh | sh

- Configure Fluentd with a TCP syslog INPUT

.. code:: bash

    vi /etc/td-agent/td-agent.conf
        <match debug.**>
          @type stdout
          @id output_stdout
        </match>
        <source>
          @type http
          @id input_http
          port 8888
        </source>
        <source>
          @type syslog
          tag debug.logstream
          port 5140
          bind 0.0.0.0
          <transport tcp>
            </transport>
        </source>

- Start service

.. code:: bash

    systemctl start td-agent.service


- Unit test

.. code:: bash

    tail -f -n 1 /var/log/td-agent/td-agent.log &
    curl -X POST -d 'json={"json":"message"}' http://localhost:8888/debug.test





