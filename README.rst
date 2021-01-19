LogStream for NGINX Controller App Sec
=======================================================================
.. contents:: Table of Contents

Introduction
==================================================
Use Case
###############

LogStream forwards http security event logs - received from NGINX Controller App Sec - to remote syslog servers (log collector, SIEM)

.. figure:: _figures/Architecture_global_direct.png

Demo
###############

.. raw:: html

    <a href="http://www.youtube.com/watch?v=BMEK_JEi3cc"><img src="http://img.youtube.com/vi/BMEK_JEi3cc/0.jpg" width="600" height="400" title="Create Identity Provider" alt="Create Identity Provider"></a>


Security consideration
#########################
No logs are stored. LogStream receives logs and then PUSH them directly to remote log collector servers.

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
NGINX Controller
###############
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-nginx_controller-create_appsec_http_forwarder``           Create/Update Forwarder                             ``playbooks/poc-nginx_controller.yaml``         ``create_appsec_http_forwarder``                ``localhost``
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================
Extra variable                                  Description
==============================================  =============================================
``extra_nginx_controller_ip``
``extra_nginx_controller_password``
``extra_nginx_controller_username``
``extra_log_collector.endpointUri``             Listener of remote syslog
``extra_log_collector.name``                    name of remote syslog
``extra_log_collector.api_key``                 Shared Key to authenticate Controller
==============================================  =============================================

.. code:: yaml
---
    activity: create_appsec_http_forwarder
    extra_log_collector:
      endpointUri: 'http://10.0.0.10:3001/forward'
      name: logstream
      api_key: TESTKEY
    extra_nginx_controller:
      ip: 10.0.0.43
      password: MyPassword!
      username: admin@acme.com

Logstream
###############
Create and launch a workflow template ``wf-create_vm_app_nginx_unit`` that includes those Job templates in this order:

=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
Job template                                                    objective                                           playbook                                        activity                                        inventory                                       limit                                           credential
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================
``poc-azure_create-vm-nginx_unit``                              Deploy a VM                                         ``playbooks/poc-azure.yaml``                    ``create-vm-nginx_unit``                        ``my_project``                                  ``localhost``                                   ``my_azure_credential``
``poc-onboarding_nginx_unit_faas_app``                          Install NGINX Unit + App                            ``playbooks/poc-nginx_vm.yaml``                 ``onboarding_nginx_unit_faas_app``              ``localhost``                                                                                   ``cred_NGINX``
=============================================================   =============================================       =============================================   =============================================   =============================================   =============================================   =============================================

==============================================  =============================================
Extra variable                                  Description
==============================================  =============================================
``extra_platform_name``                         platform name used for Azure resource group
``extra_platform_tags``                         Azure VM tags
``extra_subnet_mgt_on_premise``                 Cross management zone via VPN GW
``extra_vm``                                    Dict of VM properties
``extra_vm.name``                               VM name
``extra_vm.ip``                                 VM IP address
``extra_vm.size``                               Azure VM type
``extra_vm.availability_zone``                  Azure AZ
``extra_vm.location``                           Azure location
``extra_vm.key_data``                           admin user public key
==============================================  =============================================

.. code:: yaml
---
extra_vm:
  ip: 10.100.0.51
  name: logstream-cas
  size: Standard_B2s
  admin_username: myadmin
  availability_zone:
    - 1
  location: eastus2
  key_data: -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
extra_platform_name: TotalInbound
extra_platform_tags: environment=DMO platform=TotalInbound project=CloudBuilderf5
extra_subnet_mgt_on_premise: 10.0.0.0/24
faas_app:
  name: logstream-cas
  repo: https://github.com/nergalex/WebMap.git
  ca_pem: "-----BEGIN CERTIFICATE-----\r\n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\r\ny3fDr+Dj/wdcO7FoIWcCxWOGTg==\r\n-----END CERTIFICATE-----"
  cert_pem: "-----BEGIN CERTIFICATE-----\r\nMIIFOzCCAyOgAwIBAgIBDDANBgkqhkiG9w0BAQsFADB5MQswCQYDVQQGEwJGUjEM\r\nMAoGA1UECBMDSURGMQ4wDAYDVQQHEwVQYXJpczELMAkGA1UEChMCRjUxCzAJBgNV\r\nBAsTAkY1MRAwDgYDVQQDDAdjYV9kZW1vMSAwHgYJKoZIhvcNAQkBFhFhbC5kYWNv\r\nc3RhQGY1LmNvbTAeFw0yMDA1MjgwOTE3MDBaFw0yMTA1MjgwOTE3MDBaMIGPMQsw\r\nCQYDVQQGEwJGUjEMMAoGA1UECBMDSWRGMREwDwYDVQQHEwhTdXJlc25lczELMAkG\r\nA1UEChMCRjUxCzAJBgNVBAsTAkY1MSMwIQYDVQQDExp3ZWJob29rLmY1Y2xvdWRi\r\ndWlsZGVyLmRldjEgMB4GCSqGSIb3DQEJARYRYWwuZGFjb3N0YUBmNS5jb20wggEi\r\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEha4rFkV0uNn47gJy9pv00Uij\r\no94VTXwlBK9e7QUkp4Qk8Y/GJXcl0KZG2aaND5O7hdmi4deZO7hNgQmYfZlYB1mV\r\n0gL5JKTJyyjvzmlyV3eaZoEHki/oGg5cf+6m0nbbNTdyx4Bq+yn4NoGLP8g2IGGh\r\nH4u46U6laL8RI5y+HUTTHYP5ZXdBM2nMRDuLzqKakAj7GH1k6jr5Zd3wqLqjm6pL\r\n8xywkxw00hvlTNUqBlaSEnQGn2i2dM93IK9RKd5rlncOYSX+6D7Rr/D7/iqR1voc\r\n+XjiIsa+RznTM0CzxYxjYB4iHfanxG1IfCrpdF+F5JjHaYOH3b6goU0rTeUvAgMB\r\nAAGjgbYwgbMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUkSvkiZ53WcBAnAU/2nI9\r\nITcEODMwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD\r\nAjAlBgNVHREEHjAcghp3ZWJob29rLmY1Y2xvdWRidWlsZGVyLmRldjARBglghkgB\r\nhvhCAQEEBAMCBkAwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkq\r\nhkiG9w0BAQsFAAOCAgEAcvvle8FpaNLvCAz9IEV7GGBrPnWBFrgiKvtaBbheu0ur\r\ndb+5Ep2/1NH/jk/p1U7WdOSpedopdibVDf07dt2m09xpip5qiizAbd4oncYkkfi1\r\nU8TCOMJS8kMEJHk2YsCMki90CVKh7ZySj0E74JSi2ZophEQOIQS++2uc+gxue4mC\r\n1+fvU9mIcFXtewvIedRRcX/77Hpd43qg1Ga9KA0OVsUG+A4yEMajw9PCLLy4PAHG\r\n/hbdR5JfvYI2TdUuvVPkTosHXB34ZWtQ8xcNvnnimAoTki6+ofHsKcfjW3j29qKp\r\nCNbJSaC7Sr/m5yHHfQD1kYO9XzRfSVTgFECYQhR9chqrzeAavJj7aO3DA0PfppVN\r\n7ngk0Sgw1YveCeb+1H7njSUdQOTCwBUcmKFGPztOPKZjk2bJXiGvEPJjxvTPXI+H\r\nnPPT6/7zRJH1XLD6IjwhrSc9aWI7NuwfDJ1s0X/h4aORaf2pCS+XuZBVHqqOHH4e\r\nQGlDaHBoB0p0fw1+OIxvQNHPjJx8bHCbvC1T7OL1LxgWXHZJEYQChgkcCJtfKzvi\r\nCWo1VXB5Cj/Jab4flXBxV9hDWs8FGssBMKv8wW6OZOYuIzOs2+f1+k17razJSae/\r\nxQ0nG9P/tpRf9Dz3IPGW0aTZTSua2QYgtdfLGPna6VHHD+kmD0qupkMtXMZ3lz4=\r\n-----END CERTIFICATE-----"
  key_pem: "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEogIBAAKCAQEAxIWuKxZFdLjZ+O4Ccvab9NFIo6PeFU18JQSvXu0FJKeEJPGP\r\nxiV3JdCmRtmmjQ+Tu4XZouHXmTu4TYEJmH2ZWAdZldIC+SSkycso785pcld3mmaB\r\nB5Iv6BoOXH/uptJ22zU3cseAavsp+DaBiz/INiBhoR+LuOlOpWi/ESOcvh1E0x2D\r\n+WV3QTNpzEQ7i86impAI+xh9ZOo6+WXd8Ki6o5uqS/McsJMcNNIb5UzVKgZWkhJ0\r\nBp9otnTPdyCvUSnea5Z3DmEl/ug+0a/w+/4qkdb6HPl44iLGvkc50zNAs8WMY2Ae\r\nIh32p8RtSHwq6XRfheSYx2mDh92+oKFNK03lLwIDAQABAoIBAC7yYHEamO0RW8ED\r\n2sHr98W8WUX+V4dvQ0D0pZBfvuLKwd6xdk83lAcMmSxDwm3gUsJxb1Rh70dD5Pte\r\n4BP1rTRCTTxlNyCdiGBMkDL5dGdETeYsppZQbfFciCHAzho8HPiw9dYNorfr2FLb\r\ncob5bbLAeZIsHwzFb2xEYaCOiVtA51jSt93oDnw68DWEUpgWAxS+JD8JEQyiHetT\r\nUjGdw2aERkULtlwRU7NGMBj0Vs0Jb8vDW98bLfp2If90kgMQ1EGusSkWhaxrGu3T\r\n/o8Bf2RsWT9NCG8jLwpGgYnhKpSQ4nKNZofzQhUzYIEzPIEBQev0j21h8ooG6TWN\r\nYVlYesECgYEA7qkg0ceW1IRiSufYgUHoJCZDOkdnMK3RdX6ZZbCi/vE3DWvcwKhH\r\niM8DQjb9NLS+mlTWeR2kdd4PNBDHTRQueUHmSsZH18150B222uVcgujV8uSjwYpC\r\naqGXKrJCxtiS/DPhQYGDaWE/4PdFzu3AGxOP5phtS6FCJk+v4OqdOs0CgYEA0szQ\r\nmdps+k/TqhG9F1rlZUsS+N6knAZyuoiDhFW861+YExu0lj9fVQ5Detsbb8X81OCy\r\nw4k9tezeAyxsMl3meevEAo5Zr3gwLSaVEuZcWbrdOUL1cUpX88Pn/AYUHWiuEPrH\r\n1mRFGRtCp/mBvq1iVLaCS1VKcgwglA6k6mByl+sCgYB6SgU8GMYrfO4UrbndeZTm\r\nuQhnm2C/q8ERMF6PobPTaGwqH2PNAC0vZ8umqSCTWi30TJZdFxhHIRKvPg2xbC7o\r\nCSFknTcA2BOb1S31+eKuXXoLbKaQLDUeCFC6Gv9mfmDKhBbfBur8G02tC2ckweRW\r\nu25X3TDbuPR5Rwm6+Ny53QKBgHtOAOsuADb/AMHndGM38R0qJ+PZYBJAF1YTSlLb\r\nUBGiLjNnLmAAm8QF/uTbS5Y7CqR+9zI3khhbgJX8oyFnGczRYytXlxBzzkJq4iJX\r\nC0gVbRf0mdt18DKPsqAR8iwtsjwOZVx79Is2Dexxnzoo8263/0kPj+dcPqY8Vq0e\r\nU4mXAoGAXtvoskMH3/KLriOiyt3Sf1UrAVju+mBXJwU0b8pjTmXvrmkvFi4OYw4v\r\nFC5ybPaTMew7WLfBbEy+3ZZ9/1a/S9Gcz7LSEDzSlfx7SGMHxrOmwDmHNmxxmt5q\r\n3ZmVBPKMdZFNu1jGL2AIoo890eyQhk/L4ZAS6czrBmnkI3sT/LU=\r\n-----END RSA PRIVATE KEY-----"



    extra_availability_zone:
      - 1
    extra_key_data: -----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
    extra_location: eastus2
    extra_management_subnet_address_prefix: 10.100.0.0/24
    extra_platform_name: MyLab
    extra_platform_tags: environment=DMO platform=MyLab project=CloudBuilderf5
    extra_subnet_mgt_on_premise: 10.0.0.0/24
    extra_vm
      ip_mgt: 10.100.0.51
      vm_name: logstream-cas
    extra_vm_size: Standard_B4ms
    infra_admin_username: cyber
    faas_app_name: WebMap
    faas_app_repo: https://github.com/nergalex/WebMap.git
    extra_webhook_ca_pem: "-----BEGIN CERTIFICATE-----\r\n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\r\ny3fDr+Dj/wdcO7FoIWcCxWOGTg==\r\n-----END CERTIFICATE-----"
    extra_webhook_cert_pem: "-----BEGIN CERTIFICATE-----\r\nMIIFOzCCAyOgAwIBAgIBDDANBgkqhkiG9w0BAQsFADB5MQswCQYDVQQGEwJGUjEM\r\nMAoGA1UECBMDSURGMQ4wDAYDVQQHEwVQYXJpczELMAkGA1UEChMCRjUxCzAJBgNV\r\nBAsTAkY1MRAwDgYDVQQDDAdjYV9kZW1vMSAwHgYJKoZIhvcNAQkBFhFhbC5kYWNv\r\nc3RhQGY1LmNvbTAeFw0yMDA1MjgwOTE3MDBaFw0yMTA1MjgwOTE3MDBaMIGPMQsw\r\nCQYDVQQGEwJGUjEMMAoGA1UECBMDSWRGMREwDwYDVQQHEwhTdXJlc25lczELMAkG\r\nA1UEChMCRjUxCzAJBgNVBAsTAkY1MSMwIQYDVQQDExp3ZWJob29rLmY1Y2xvdWRi\r\ndWlsZGVyLmRldjEgMB4GCSqGSIb3DQEJARYRYWwuZGFjb3N0YUBmNS5jb20wggEi\r\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEha4rFkV0uNn47gJy9pv00Uij\r\no94VTXwlBK9e7QUkp4Qk8Y/GJXcl0KZG2aaND5O7hdmi4deZO7hNgQmYfZlYB1mV\r\n0gL5JKTJyyjvzmlyV3eaZoEHki/oGg5cf+6m0nbbNTdyx4Bq+yn4NoGLP8g2IGGh\r\nH4u46U6laL8RI5y+HUTTHYP5ZXdBM2nMRDuLzqKakAj7GH1k6jr5Zd3wqLqjm6pL\r\n8xywkxw00hvlTNUqBlaSEnQGn2i2dM93IK9RKd5rlncOYSX+6D7Rr/D7/iqR1voc\r\n+XjiIsa+RznTM0CzxYxjYB4iHfanxG1IfCrpdF+F5JjHaYOH3b6goU0rTeUvAgMB\r\nAAGjgbYwgbMwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUkSvkiZ53WcBAnAU/2nI9\r\nITcEODMwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD\r\nAjAlBgNVHREEHjAcghp3ZWJob29rLmY1Y2xvdWRidWlsZGVyLmRldjARBglghkgB\r\nhvhCAQEEBAMCBkAwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0ZTANBgkq\r\nhkiG9w0BAQsFAAOCAgEAcvvle8FpaNLvCAz9IEV7GGBrPnWBFrgiKvtaBbheu0ur\r\ndb+5Ep2/1NH/jk/p1U7WdOSpedopdibVDf07dt2m09xpip5qiizAbd4oncYkkfi1\r\nU8TCOMJS8kMEJHk2YsCMki90CVKh7ZySj0E74JSi2ZophEQOIQS++2uc+gxue4mC\r\n1+fvU9mIcFXtewvIedRRcX/77Hpd43qg1Ga9KA0OVsUG+A4yEMajw9PCLLy4PAHG\r\n/hbdR5JfvYI2TdUuvVPkTosHXB34ZWtQ8xcNvnnimAoTki6+ofHsKcfjW3j29qKp\r\nCNbJSaC7Sr/m5yHHfQD1kYO9XzRfSVTgFECYQhR9chqrzeAavJj7aO3DA0PfppVN\r\n7ngk0Sgw1YveCeb+1H7njSUdQOTCwBUcmKFGPztOPKZjk2bJXiGvEPJjxvTPXI+H\r\nnPPT6/7zRJH1XLD6IjwhrSc9aWI7NuwfDJ1s0X/h4aORaf2pCS+XuZBVHqqOHH4e\r\nQGlDaHBoB0p0fw1+OIxvQNHPjJx8bHCbvC1T7OL1LxgWXHZJEYQChgkcCJtfKzvi\r\nCWo1VXB5Cj/Jab4flXBxV9hDWs8FGssBMKv8wW6OZOYuIzOs2+f1+k17razJSae/\r\nxQ0nG9P/tpRf9Dz3IPGW0aTZTSua2QYgtdfLGPna6VHHD+kmD0qupkMtXMZ3lz4=\r\n-----END CERTIFICATE-----"
    extra_webhook_key_pem: "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEogIBAAKCAQEAxIWuKxZFdLjZ+O4Ccvab9NFIo6PeFU18JQSvXu0FJKeEJPGP\r\nxiV3JdCmRtmmjQ+Tu4XZouHXmTu4TYEJmH2ZWAdZldIC+SSkycso785pcld3mmaB\r\nB5Iv6BoOXH/uptJ22zU3cseAavsp+DaBiz/INiBhoR+LuOlOpWi/ESOcvh1E0x2D\r\n+WV3QTNpzEQ7i86impAI+xh9ZOo6+WXd8Ki6o5uqS/McsJMcNNIb5UzVKgZWkhJ0\r\nBp9otnTPdyCvUSnea5Z3DmEl/ug+0a/w+/4qkdb6HPl44iLGvkc50zNAs8WMY2Ae\r\nIh32p8RtSHwq6XRfheSYx2mDh92+oKFNK03lLwIDAQABAoIBAC7yYHEamO0RW8ED\r\n2sHr98W8WUX+V4dvQ0D0pZBfvuLKwd6xdk83lAcMmSxDwm3gUsJxb1Rh70dD5Pte\r\n4BP1rTRCTTxlNyCdiGBMkDL5dGdETeYsppZQbfFciCHAzho8HPiw9dYNorfr2FLb\r\ncob5bbLAeZIsHwzFb2xEYaCOiVtA51jSt93oDnw68DWEUpgWAxS+JD8JEQyiHetT\r\nUjGdw2aERkULtlwRU7NGMBj0Vs0Jb8vDW98bLfp2If90kgMQ1EGusSkWhaxrGu3T\r\n/o8Bf2RsWT9NCG8jLwpGgYnhKpSQ4nKNZofzQhUzYIEzPIEBQev0j21h8ooG6TWN\r\nYVlYesECgYEA7qkg0ceW1IRiSufYgUHoJCZDOkdnMK3RdX6ZZbCi/vE3DWvcwKhH\r\niM8DQjb9NLS+mlTWeR2kdd4PNBDHTRQueUHmSsZH18150B222uVcgujV8uSjwYpC\r\naqGXKrJCxtiS/DPhQYGDaWE/4PdFzu3AGxOP5phtS6FCJk+v4OqdOs0CgYEA0szQ\r\nmdps+k/TqhG9F1rlZUsS+N6knAZyuoiDhFW861+YExu0lj9fVQ5Detsbb8X81OCy\r\nw4k9tezeAyxsMl3meevEAo5Zr3gwLSaVEuZcWbrdOUL1cUpX88Pn/AYUHWiuEPrH\r\n1mRFGRtCp/mBvq1iVLaCS1VKcgwglA6k6mByl+sCgYB6SgU8GMYrfO4UrbndeZTm\r\nuQhnm2C/q8ERMF6PobPTaGwqH2PNAC0vZ8umqSCTWi30TJZdFxhHIRKvPg2xbC7o\r\nCSFknTcA2BOb1S31+eKuXXoLbKaQLDUeCFC6Gv9mfmDKhBbfBur8G02tC2ckweRW\r\nu25X3TDbuPR5Rwm6+Ny53QKBgHtOAOsuADb/AMHndGM38R0qJ+PZYBJAF1YTSlLb\r\nUBGiLjNnLmAAm8QF/uTbS5Y7CqR+9zI3khhbgJX8oyFnGczRYytXlxBzzkJq4iJX\r\nC0gVbRf0mdt18DKPsqAR8iwtsjwOZVx79Is2Dexxnzoo8263/0kPj+dcPqY8Vq0e\r\nU4mXAoGAXtvoskMH3/KLriOiyt3Sf1UrAVju+mBXJwU0b8pjTmXvrmkvFi4OYw4v\r\nFC5ybPaTMew7WLfBbEy+3ZZ9/1a/S9Gcz7LSEDzSlfx7SGMHxrOmwDmHNmxxmt5q\r\n3ZmVBPKMdZFNu1jGL2AIoo890eyQhk/L4ZAS6czrBmnkI3sT/LU=\r\n-----END RSA PRIVATE KEY-----"

Uninstallation
==================================================

Configuration
==================================================
- Install `Postman <https://www.postman.com/>`_
- Import collection LogStream_cas.postman_collection.json
- Use `declare` entry point to configure entirely LogStream. Refer to API Dev Portal for parameter and allowed values.
- Use `action` entry point to start/stop the engine.
- Use `declare` anytime you need to reconfigure LogStream and launch `restart` `action` to apply the new configuration.
- Note that the last `declaration` is saved locally

API reference
==================================================
Access to API Dev Portal with your browser ``http://<extra_vm.ip_mgt>:8080/apidocs/``
