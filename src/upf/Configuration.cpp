/**
 * Auto-generated file. Do not modify this file.
 * Check Configuration.cpp.in.
 */
#include "Configuration.h"
#include <string>
#include <utils/LogDefines.h>

// Values get from enviroment variable GTP_INTERFACE and UDP_INTERFACE
// Consider to update these variables with you want to update the default values.
std::string Configuration::sGTPInterface = "";
std::string Configuration::sUDPInterface = "";
unsigned char Configuration::sIsSocketBufferEnabled = 0;

Configuration::Configuration(int argc, char **argv)
{
  if(argc >= 2) {
    Configuration::sGTPInterface = argv[1];
    Configuration::sUDPInterface = argv[2];
  }

  LOG_DBG("GTP Inteface {}", Configuration::sGTPInterface);
  LOG_DBG("UDP Inteface {}", Configuration::sUDPInterface);
  for(int i = 1; i < argc; ++i) {
    LOG_DBG("arg {} = {}", i, argv[i]);
  }
}
