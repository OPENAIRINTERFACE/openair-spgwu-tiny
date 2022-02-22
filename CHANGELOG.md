# RELEASE NOTES: #

## v1.2.0 -- February 2022 ##

* Obsolescence of Legacy OAI-MME
* Build fixes
* Docker image layer optimization

## v1.1.5 -- December 2021 ##

* Disable association request if NF registration is enabled

## v1.1.4 -- October 2021 ##

* Fix build issue
* Fix GTPU DL encapsulation: 8 extraneous bytes

## v1.1.3 -- October 2021 ##

* Adding 5G features
  - HTTP2 support

## v1.1.2 -- July 2021 ##

* Adding 5G features
  - NRF discovery and FQDN support

## v1.1.1 -- March 2021 ##

* GTP-U extension headers for 5G support
  - disabled by default for 4G usage

## v1.1.0 -- February 2021 ##

*  Cloud-native support
*  RHEL8 support
*  A lot of bug fixes/improvements
   -  TCP checksum fix --> better TCP throughput
   -  Multi-Threading
   -  Protection to prevent running multiple times the executable
   -  ...
*  Last release before Multi-SPGW-U-instance support

## v1.0.0 -- May 2019 ##

* First release, Able to serve a MME with basic attach, detach, release, paging procedures, default bearer only.
