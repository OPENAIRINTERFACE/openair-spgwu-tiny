<h1 align="center">
    <a href="https://openairinterface.org/"><img src="https://openairinterface.org/wp-content/uploads/2015/06/cropped-oai_final_logo.png" alt="OAI" width="550"></a>
</h1>

------------------------------------------------------------------------------

                             OPENAIR-CN
    An implementation of the Evolved Packet Core network.
    
------------------------------------------------------------------------------
    
<p align="center">
    <a href="https://github.com/OPENAIRINTERFACE/openair-spgwu-tiny/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-OAI--Public--V1.1-blue" alt="License"></a>
    <a href="https://jenkins-oai.eurecom.fr/job/OAI-CN-SPGWU-TINY/"><img src="https://img.shields.io/jenkins/build?jobUrl=https%3A%2F%2Fjenkins-oai.eurecom.fr%2Fjob%2FOAI-CN-SPGWU-TINY%2F&label=build%20SPGWU-TINY"></a>
</p>

  Openair-cn is an implementation of the 3GPP specifications concerning the 
  Evolved Packet Core Networks, that means it contains the implementation of the
  following network elements:

  * MME,
  * HSS,
  * S-GW+P-GW.
  
  Each element implementation has its own repository: this repository (`openair-spgwu-tiny`) is meant for SPGW-U.

# openair-spgwu-tiny

In the `Control / User Planes Separation` (a.k.a. `CUPS`) of SPGW, only the SPGW-U (User Plane) implementation is available in this repo.

This component can be deployed:

*  As first intended as `4G-LTE` Core Network User Plane function.
*  But now also as a `5G` Core Network User Plane function (a.k.a. `UPF`)

It is distributed under `OAI Public License V1.1`. See [OAI Website for more details](https://www.openairinterface.org/?page_id=698).

The text for `OAI Public License V1.1` is also available under [LICENSE](LICENSE) file in the same directory.

# Where to start

  The Openair-cn SPGW-U code is written, executed, and tested on `UBUNTU` server `bionic` version.

  It is also built and tested on `RHEL8` platform (such as `Openshift`).

  More details on the deployment options and the supported feature set is available on this [page](docs/FEATURE_SET.md).

# Collaborative work

  This source code is managed through a GITHUB, a collaborative development platform

  Process is explained in [CONTRIBUTING](CONTRIBUTING.md) file.

# Directory structure

<pre>
openair-spgwu-tiny
├── build :       Build directory, contains targets and object files generated by compilation of network functions. 
│   ├── log :     Directory containing build log files.
│   ├── scripts : Directory containing scripts for building network functions.
│   └── spgw_u :  Directory containing CMakefile.txt and object files generated by compilation of SPGW-U network function. 
├── ci-scripts :  Directory containing scripts for the CI process.
├── docker :      Directory containing dockerfiles to create images.
├── docs :        Directory containing documentation on the supported feature set.
├── etc :         Directory containing the configuration files to be deployed for each network function.
├── openshift :   Directory containing YAML files for build within OpenShift context.
├── scripts :     Directory containing entrypoint script for container images.
└── src :         Source files of network functions.
    ├── common :    Common header files
    │   ├── msg :   ITTI messages definitions.
    │   └── utils : Common utilities.
    ├── gtpv1u :    Generic GTPV1-U stack implementation
    ├── gtpv2c :    Generic GTPV2-C stack implementation
    ├── itti :      Inter task interface 
    ├── oai_spgwu : SPGW-U main directory, contains the "main" CMakeLists.txt file.
    │   └── simpleswitch : Very Basic Switch implementation.
    ├── pfcp :      Generic PFCP stack implementation.
    └── udp :       UDP server implementation.
</pre>

