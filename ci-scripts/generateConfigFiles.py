#/*
# * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# * contributor license agreements.  See the NOTICE file distributed with
# * this work for additional information regarding copyright ownership.
# * The OpenAirInterface Software Alliance licenses this file to You under
# * the OAI Public License, Version 1.1  (the "License"); you may not use this file
# * except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *	  http://www.openairinterface.org/?page_id=698
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *-------------------------------------------------------------------------------
# * For more information about the OpenAirInterface (OAI) Software Alliance:
# *	  contact@openairinterface.org
# */
#---------------------------------------------------------------------

import os
import re
import sys
import ipaddress

class spgwuConfigGen():
	def __init__(self):
		self.kind = ''
		self.s1u_name = ''
		self.sxu_name = ''
		self.spgwc0_ip_addr = ipaddress.ip_address('0.0.0.0')
		self.fromDockerFile = False
		self.envForEntrypoint = False
		self.networkUeIp = ipaddress.ip_network('12.1.1.0/24')
		self.networkUeNatOption = 'no'

	def GenerateSpgwuConfigurer(self):
		spgwuFile = open('./spgwu-cfg.sh', 'w')
		spgwuFile.write('#!/bin/bash\n')
		spgwuFile.write('\n')
		if self.fromDockerFile:
			spgwuFile.write('cd /openair-spgwu-tiny\n')
		else:
			spgwuFile.write('cd /home\n')
		spgwuFile.write('\n')
		spgwuFile.write('INSTANCE=1\n')
		if self.fromDockerFile:
			spgwuFile.write('PREFIX=\'/oai-upf/etc\'\n')
		else:
			spgwuFile.write('PREFIX=\'/usr/local/etc/oai\'\n')
		spgwuFile.write('\n')

		if not self.fromDockerFile:
			spgwuFile.write('mkdir -p $PREFIX\n')
			spgwuFile.write('cp etc/upf.conf $PREFIX\n')
			spgwuFile.write('\n')

		spgwuFile.write('declare -A SPGWU_CONF\n')
		spgwuFile.write('\n')
		spgwuFile.write('SPGWU_CONF[@INSTANCE@]=$INSTANCE\n')
		spgwuFile.write('SPGWU_CONF[@PID_DIRECTORY@]=\'/var/run\'\n')
		spgwuFile.write('SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_N3@]=\'' + self.s1u_name + '\'\n')
		spgwuFile.write('SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SX@]=\'' + self.sxu_name + '\'\n')
		# SGI is fixed on SGI
		spgwuFile.write('SPGWU_CONF[@PGW_INTERFACE_NAME_FOR_SGI@]=\'eth0\'\n')
		spgwuFile.write('SPGWU_CONF[@SPGWC0_IP_ADDRESS@]=\'' + str(self.spgwc0_ip_addr) + '\'\n')
		spgwuFile.write('SPGWU_CONF[@NETWORK_UE_IP@]=\'' + str(self.networkUeIp) + '\'\n')
		spgwuFile.write('SPGWU_CONF[@NETWORK_UE_NAT_OPTION@]=\'' + self.networkUeNatOption + '\'\n')
		# Adding Multi-threading options
		spgwuFile.write('SPGWU_CONF[@THREAD_S1U_PRIO@]=80\n')
		spgwuFile.write('SPGWU_CONF[@S1U_THREADS@]=8\n')
		spgwuFile.write('SPGWU_CONF[@THREAD_SX_PRIO@]=81\n')
		spgwuFile.write('SPGWU_CONF[@SX_THREADS@]=1\n')
		spgwuFile.write('SPGWU_CONF[@THREAD_SGI_PRIO@]=80\n')
		spgwuFile.write('SPGWU_CONF[@SGI_THREADS@]=8\n')
		spgwuFile.write('SPGWU_CONF[@BYPASS_UL_PFCP_RULES@]=\'no\'\n')
		spgwuFile.write('\n')
		spgwuFile.write('for K in "${!SPGWU_CONF[@]}"; do \n')
		spgwuFile.write('  egrep -lRZ "$K" $PREFIX | xargs -0 -l sed -i -e "s|$K|${SPGWU_CONF[$K]}|g"\n')
		spgwuFile.write('done\n')
		spgwuFile.write('\n')
		spgwuFile.write('exit 0\n')
		spgwuFile.close()

	def GenerateSpgwuEnvList(self):
		spgwuFile = open('./spgwu-env.list', 'w')
		spgwuFile.write('# Environment Variables used by the OAI-UPF-TINY Entrypoint Script\n')
		spgwuFile.write('MCC=208\n')
		spgwuFile.write('MNC=99\n')
		spgwuFile.write('MNC03=099\n')
		spgwuFile.write('REALM=openairinterface.org\n')
		spgwuFile.write('GW_ID=1\n')
		spgwuFile.write('PID_DIRECTORY=/var/run\n')
		spgwuFile.write('SGW_INTERFACE_NAME_FOR_N3=' + self.s1u_name + '\n')
		spgwuFile.write('SGW_INTERFACE_NAME_FOR_SX=' + self.sxu_name + '\n')
		spgwuFile.write('PGW_INTERFACE_NAME_FOR_SGI=eth0\n')
		spgwuFile.write('SPGWC0_IP_ADDRESS=' + str(self.spgwc0_ip_addr) + '\n')
		spgwuFile.write('NETWORK_UE_IP=' + str(self.networkUeIp) + '\n')
		spgwuFile.write('NETWORK_UE_NAT_OPTION=' + self.networkUeNatOption + '\n')
		# Adding Multi-threading options
		spgwuFile.write('THREAD_S1U_PRIO=80\n')
		spgwuFile.write('S1U_THREADS=8\n')
		spgwuFile.write('THREAD_SX_PRIO=81\n')
		spgwuFile.write('SX_THREADS=1\n')
		spgwuFile.write('THREAD_SGI_PRIO=80\n')
		spgwuFile.write('SGI_THREADS=8\n')
		spgwuFile.write('BYPASS_UL_PFCP_RULES=no\n')
		spgwuFile.close()

#-----------------------------------------------------------
# Usage()
#-----------------------------------------------------------
def Usage():
	print('----------------------------------------------------------------------------------------------------------------------')
	print('generateConfigFiles.py')
	print('   Prepare a bash script to be run in the workspace where UPF-TINY is being built.')
	print('   That bash script will copy configuration template files and adapt to your configuration.')
	print('----------------------------------------------------------------------------------------------------------------------')
	print('Usage: python3 generateConfigFiles.py [options]')
	print('  --help  Show this help.')
	print('------------------------------------------------------------------------------------------------- UPF Options -----')
	print('  --kind=UPF')
	print('  --sxc_ip_addr=[SPGW-C SX IP address]')
	print('  --sxu=[UPF SX Interface Name]')
	print('  --s1u=[UPF S1-U Interface Name]')
	print('  --from_docker_file')
	print('------------------------------------------------------------------------------------------- UPF Not Mandatory -----')
	print('  --network_ue_ip=[UE IP pool range in CICDR format, for example 12.1.1.0/24. The attached UE will be allocated an IP address in that range.]')
	print('  --network_ue_nat_option=[yes or no, no is default]')
	print('  --env_for_entrypoint	[generates a spgwc-env.list interpreted by the entrypoint]')

argvs = sys.argv
argc = len(argvs)
cwd = os.getcwd()

mySpgwuCfg = spgwuConfigGen()

while len(argvs) > 1:
	myArgv = argvs.pop(1)
	if re.match('^\-\-help$', myArgv, re.IGNORECASE):
		Usage()
		sys.exit(0)
	elif re.match('^\-\-kind=(.+)$', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-kind=(.+)$', myArgv, re.IGNORECASE)
		mySpgwuCfg.kind = matchReg.group(1)
	elif re.match('^\-\-sxu=(.+)$', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-sxu=(.+)$', myArgv, re.IGNORECASE)
		mySpgwuCfg.sxu_name = matchReg.group(1)
	elif re.match('^\-\-sxc_ip_addr=(.+)$', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-sxc_ip_addr=(.+)$', myArgv, re.IGNORECASE)
		mySpgwuCfg.spgwc0_ip_addr = ipaddress.ip_address(matchReg.group(1))
	elif re.match('^\-\-s1u=(.+)$', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-s1u=(.+)$', myArgv, re.IGNORECASE)
		mySpgwuCfg.s1u_name = matchReg.group(1)
	elif re.match('^\-\-from_docker_file', myArgv, re.IGNORECASE):
		mySpgwuCfg.fromDockerFile = True
	elif re.match('^\-\-env_for_entrypoint', myArgv, re.IGNORECASE):
		mySpgwuCfg.envForEntrypoint = True
	elif re.match('^\-\-network_ue_ip', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-network_ue_ip=(.+)$', myArgv, re.IGNORECASE)
		mySpgwuCfg.networkUeIp = ipaddress.ip_network(matchReg.group(1))
	elif re.match('^\-\-network_ue_nat_option', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-network_ue_nat_option=(.+)$', myArgv, re.IGNORECASE)
		natOption = matchReg.group(1)
		if natOption == 'yes' or natOption == 'Yes' or natOption == 'YES':
			mySpgwuCfg.networkUeNatOption = 'yes'
	else:
		Usage()
		sys.exit('Invalid Parameter: ' + myArgv)

if mySpgwuCfg.kind == '':
	Usage()
	sys.exit('missing kind parameter')

if mySpgwuCfg.kind == 'UPF':
	if mySpgwuCfg.sxu_name == '':
		Usage()
		sys.exit('missing SX Interface Name on UPF container')
	elif mySpgwuCfg.s1u_name == '':
		Usage()
		sys.exit('missing S1-U Interface Name on UPF container')
	elif str(mySpgwuCfg.spgwc0_ip_addr) == '0.0.0.0':
		Usage()
		sys.exit('missing SPGW-C #0 IP address on SX interface')
	else:
		if mySpgwuCfg.envForEntrypoint:
			mySpgwuCfg.GenerateSpgwuEnvList()
		else:
			mySpgwuCfg.GenerateSpgwuConfigurer()
		sys.exit(0)
else:
	Usage()
	sys.exit('invalid kind parameter')
