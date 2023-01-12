# jinj2-generated configuration file #

We are switching to `python3-jinja2` tool in order to generate more complex configuration for our 5G core network functions.

Pre-requisites: install python3 and jinja2 packages:

```bash
sudo apt-get install -y python3 python3-jinja2
# or
sudo yum install -y python3 python3-pip
pip3 install jinja2
```

In a container deployment, you will still have to provide environment variables through a `docker-compose-file` or helm charts.

But you can also emulate how the entrypoint behaves locally on your workspace

## LTE 4G Legacy configuration ##

Create a `test-jinja.sh` file and edit it:

```bash
$ vi test-jinja.sh
#!/bin/bash

cp etc/spgw_u.conf etc/spgw_u_copy.conf
export CONFIG_FILE=./etc/spgw_u_copy.conf
export MOUNT_CONFIG=NO
export TZ=Europe/Paris
export PID_DIRECTORY=/var/run
#export SGW_INTERFACE_NAME_FOR_S1U_S12_S4_UP=eth0
#export PGW_INTERFACE_NAME_FOR_SGI=eth0
#export SGW_INTERFACE_NAME_FOR_SX=eth0
export SPGWC0_IP_ADDRESS=192.168.61.70
export NETWORK_UE_IP=12.0.0.0/24
export NETWORK_UE_NAT_OPTION=yes
export MCC=208
export MNC=96
export MNC03=096
export TAC=1
export GW_ID=1
export REALM=openairinterface.org

./scripts/entrypoint.py
$ chmod 755 test-jinja.sh
$ ./test-jinja.sh
Configuration file ./etc/spgw_u_copy.conf is ready
```

## 5G SA Core Network configuration ##

Create a `test-jinja-5g.sh` file and edit it:

```bash
$ vi test-jinja-5g.sh
#!/bin/bash

cp etc/spgw_u.conf etc/spgw_u_copy.conf
export CONFIG_FILE=./etc/spgw_u_copy.conf
export MOUNT_CONFIG=NO
export TZ=Europe/Paris
export PID_DIRECTORY=/var/run
export SGW_INTERFACE_NAME_FOR_S1U_S12_S4_UP=eth0
export SGW_INTERFACE_NAME_FOR_SX=eth0
export PGW_INTERFACE_NAME_FOR_SGI=eth0
export NETWORK_UE_NAT_OPTION=yes
export NETWORK_UE_IP=12.1.1.0/24
export BYPASS_UL_PFCP_RULES=no
export MCC=208
export MNC=95
export MNC03=095
export TAC=40960
export GW_ID=1
export THREAD_S1U_PRIO=80
export S1U_THREADS=8
export THREAD_SX_PRIO=81
export SX_THREADS=1
export THREAD_SGI_PRIO=80
export SGI_THREADS=8
export REALM=openairinterface.org
export ENABLE_5G_FEATURES=yes
export REGISTER_NRF=yes
export USE_FQDN_NRF=yes
export UPF_FQDN_5G=oai-spgwu
export NRF_IPV4_ADDRESS=192.168.70.130
export NRF_PORT=80
export NRF_API_VERSION=v1
export NRF_FQDN=oai-nrf
export NSSAI_SST_0=1
export NSSAI_SD_0=0xFFFFFF
export DNN_0=oai
export NSSAI_SST_1=1
export NSSAI_SD_1=1
export DNN_1=oai.ipv4
export NSSAI_SST_2=222
export NSSAI_SD_2=123
export DNN_2=default

./scripts/entrypoint.py
$ chmod 755 test-jinja-5g.sh
$ ./test-jinja-5g.sh
Configuration file ./etc/spgw_u_copy.conf is ready
```

## List of fields ##

Here is the current list of fields, with their mandatory status and any default values.

If there is no default value associated to a field, it means it is **MANDATORY** to provide one.

| Field Name | Mandatory / Optional | 4G / 5G / Both | Default value if any |
|:-----------|----------------------|----------------|---------------------:|
| GW_ID      | Mandatory | 4G | |
| MNC03      | Mandatory | 4G | |
| MCC        | Mandatory | 4G | |
| REALM      | Mandatory | 4G | |
| PID_DIRECTORY | Mandatory | 4G and 5G | |
| SGW_INTERFACE_NAME_FOR_S1U_S12_S4_UP | Optional | 4G and 5G | eth0 |
| THREAD_S1U_PRIO | Optional | 4G and 5G | 80 |
| S1U_THREADS | Optional | 4G and 5G | 8 |
| SGW_INTERFACE_NAME_FOR_SX | Optional | 4G and 5G | eth0 |
| THREAD_SX_PRIO | Optional | 4G and 5G | 81 |
| SX_THREADS | Optional | 4G and 5G | 1 |
| PGW_INTERFACE_NAME_FOR_SGI | Optional | 4G and 5G | eth0 |
| THREAD_SGI_PRIO | Optional | 4G and 5G | 80 |
| SGI_THREADS | Optional | 4G and 5G | 8 |
| NETWORK_UE_NAT_OPTION | Optional | 4G and 5G | no |
| NETWORK_UE_IP | Mandatory | 4G and 5G | |
| BYPASS_UL_PFCP_RULES | Optional | 4G and 5G | no |
| SPGWC_HOSTNAME | Optional | 4G | |
| SPGWC0_IP_ADDRESS | Mandatory | 4G | mandatory if SPGWC_HOSTNAME undefined |
| ENABLE_5G_FEATURES | Optional | 5G | no |
| REGISTER_NRF | Optional | 5G | no |
| USE_FQDN_NRF | Optional | 5G | no |
| UPF_FQDN_5G | Optional | 5G | |
| NRF_HOSTNAME | Optional | 5G | |
| NRF_PORT | Optional | 5G | 80 |
| HTTP_VERSION | Optional | 5G | 1 |
| NRF_API_VERSION | Optional | 5G | v1 |
| NRF_FQDN | Optional | 5G | |
| NSSAI_SST_0 | Optional | 5G | |
| NSSAI_SD_0 | Optional | 5G | 0xFFFFFF |
| DNN_0 | Optional | 5G | |

