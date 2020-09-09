#/*
# * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# * contributor license agreements.  See the NOTICE file distributed with
# * this work for additional information regarding copyright ownership.
# * The OpenAirInterface Software Alliance licenses this file to You under
# * the OAI Public License, Version 1.1  (the "License"); you may not use this file
# * except in compliance with the License.
# * You may obtain a copy of the License at
# *
# *      http://www.openairinterface.org/?page_id=698
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *-------------------------------------------------------------------------------
# * For more information about the OpenAirInterface (OAI) Software Alliance:
# *      contact@openairinterface.org
# */
#---------------------------------------------------------------------

import os
import re
import sys

class spgwuConfigGen():
	def __init__(self):
		self.kind = ''
		self.s1u_name = ''
		self.sxu_name = ''
		self.spgwc0_ip_addr = ''
		self.fromDockerFile = False

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
			spgwuFile.write('PREFIX=\'/openair-spgwu-tiny/etc\'\n')
		else:
			spgwuFile.write('PREFIX=\'/usr/local/etc/oai\'\n')
		spgwuFile.write('\n')

		if not self.fromDockerFile:
			spgwuFile.write('mkdir -p $PREFIX\n')
			spgwuFile.write('cp etc/spgw_u.conf $PREFIX\n')
			spgwuFile.write('\n')

		spgwuFile.write('declare -A SPGWU_CONF\n')
		spgwuFile.write('\n')
		spgwuFile.write('SPGWU_CONF[@INSTANCE@]=$INSTANCE\n')
		spgwuFile.write('SPGWU_CONF[@PID_DIRECTORY@]=\'/var/run\'\n')
		spgwuFile.write('SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_S1U_S12_S4_UP@]=\'' + self.s1u_name + '\'\n')
		spgwuFile.write('SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SX@]=\'' + self.sxu_name + '\'\n')
		# SGI is fixed on SGI
		spgwuFile.write('SPGWU_CONF[@SGW_INTERFACE_NAME_FOR_SGI@]=\'eth0\'\n')
		spgwuFile.write('SPGWU_CONF[@SPGWC0_IP_ADDRESS@]=\'' + self.spgwc0_ip_addr + '\'\n')
		spgwuFile.write('\n')
		spgwuFile.write('for K in "${!SPGWU_CONF[@]}"; do \n')
		spgwuFile.write('  egrep -lRZ "$K" $PREFIX | xargs -0 -l sed -i -e "s|$K|${SPGWU_CONF[$K]}|g"\n')
		spgwuFile.write('done\n')
		spgwuFile.write('\n')
		spgwuFile.write('exit 0\n')
		spgwuFile.close()

#-----------------------------------------------------------
# Usage()
#-----------------------------------------------------------
def Usage():
	print('----------------------------------------------------------------------------------------------------------------------')
	print('generateConfigFiles.py')
	print('   Prepare a bash script to be run in the workspace where SPGW-U-TINY is being built.')
	print('   That bash script will copy configuration template files and adapt to your configuration.')
	print('----------------------------------------------------------------------------------------------------------------------')
	print('Usage: python3 generateConfigFiles.py [options]')
	print('  --help  Show this help.')
	print('------------------------------------------------------------------------------------------------- SPGW-U Options -----')
	print('  --kind=SPGW-U')
	print('  --sxc_ip_addr=[SPGW-C SX IP address]')
	print('  --sxu=[SPGW-U SX Interface Name]')
	print('  --s1u=[SPGW-U S1-U Interface Name]')
	print('  --from_docker_file')

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
		mySpgwuCfg.spgwc0_ip_addr = matchReg.group(1)
	elif re.match('^\-\-s1u=(.+)$', myArgv, re.IGNORECASE):
		matchReg = re.match('^\-\-s1u=(.+)$', myArgv, re.IGNORECASE)
		mySpgwuCfg.s1u_name = matchReg.group(1)
	elif re.match('^\-\-from_docker_file', myArgv, re.IGNORECASE):
		mySpgwuCfg.fromDockerFile = True
	else:
		Usage()
		sys.exit('Invalid Parameter: ' + myArgv)

if mySpgwuCfg.kind == '':
	Usage()
	sys.exit('missing kind parameter')

if mySpgwuCfg.kind == 'SPGW-U':
	if mySpgwuCfg.sxu_name == '':
		Usage()
		sys.exit('missing SX Interface Name on SPGW-U container')
	elif mySpgwuCfg.s1u_name == '':
		Usage()
		sys.exit('missing S1-U Interface Name on SPGW-U container')
	elif mySpgwuCfg.spgwc0_ip_addr == '':
		Usage()
		sys.exit('missing SPGW-C #0 IP address on SX interface')
	else:
		mySpgwuCfg.GenerateSpgwuConfigurer()
		sys.exit(0)
else:
	Usage()
	sys.exit('invalid kind parameter')
