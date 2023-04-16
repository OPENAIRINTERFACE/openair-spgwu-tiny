/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file upf_config.hpp
 * \brief
 * \author Lionel Gauthier
 * \company Eurecom
 * \email: lionel.gauthier@eurecom.fr
 */

#ifndef FILE_UPF_CONFIG_HPP_SEEN
#define FILE_UPF_CONFIG_HPP_SEEN

#include "3gpp_29.244.h"
#include "3gpp_29.510.h"
#include "3gpp_23.003.h"
#include "gtpv1u.hpp"
#include "pfcp.hpp"
#include "thread_sched.hpp"
#include <libconfig.h++>
#include <mutex>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>

namespace upf {

#define UPF_CONFIG_STRING_UPF_CONFIG "UPF"
#define UPF_CONFIG_STRING_PID_DIRECTORY "PID_DIRECTORY"
#define UPF_CONFIG_STRING_INSTANCE "INSTANCE"
#define UPF_CONFIG_STRING_FQDN "FQDN"
#define UPF_CONFIG_STRING_INTERFACES "INTERFACES"
#define UPF_CONFIG_STRING_INTERFACE_NAME "INTERFACE_NAME"
#define UPF_CONFIG_STRING_IPV4_ADDRESS "IPV4_ADDRESS"
#define UPF_CONFIG_STRING_PORT "PORT"
#define UPF_CONFIG_STRING_SCHED_PARAMS "SCHED_PARAMS"
#define UPF_CONFIG_STRING_THREAD_RD_CPU_ID "CPU_ID"
#define UPF_CONFIG_STRING_THREAD_RD_SCHED_POLICY "SCHED_POLICY"
#define UPF_CONFIG_STRING_THREAD_RD_SCHED_PRIORITY "SCHED_PRIORITY"
#define UPF_CONFIG_STRING_THREAD_POOL_SIZE "THREAD_POOL_SIZE"
#define UPF_CONFIG_STRING_INTERFACE_N3 "N3"
#define UPF_CONFIG_STRING_INTERFACE_N4 "N4"
#define UPF_CONFIG_STRING_INTERFACE_N6 "N6"
#define UPF_CONFIG_STRING_PDN_NETWORK_LIST "PDN_NETWORK_LIST"
#define UPF_CONFIG_STRING_NETWORK_IPV4 "NETWORK_IPV4"
#define UPF_CONFIG_STRING_NETWORK_IPV6 "NETWORK_IPV6"
#define UPF_CONFIG_STRING_ADDRESS_PREFIX_DELIMITER "/"
#define UPF_CONFIG_STRING_SNAT "SNAT"
#define UPF_CONFIG_STRING_MAX_PFCP_SESSIONS "MAX_PFCP_SESSIONS"
#define UPF_CONFIG_STRING_SMF_LIST "SMF_LIST"
#define UPF_CONFIG_STRING_ITTI_TASKS "ITTI_TASKS"
#define UPF_CONFIG_STRING_ITTI_TIMER_SCHED_PARAMS "ITTI_TIMER_SCHED_PARAMS"
#define UPF_CONFIG_STRING_S1U_SCHED_PARAMS "S1U_SCHED_PARAMS"
#define UPF_CONFIG_STRING_SX_SCHED_PARAMS "SX_SCHED_PARAMS"
#define UPF_CONFIG_STRING_SMF_APP_SCHED_PARAMS "SMF_APP_SCHED_PARAMS"
#define UPF_CONFIG_STRING_ASYNC_CMD_SCHED_PARAMS "ASYNC_CMD_SCHED_PARAMS"
#define UPF_CONFIG_STRING_NON_STANDART_FEATURES "NON_STANDART_FEATURES"
#define UPF_CONFIG_STRING_BYPASS_UL_PFCP_RULES "BYPASS_UL_PFCP_RULES"

#define UPF_CONFIG_STRING_5G_FEATURES "SUPPORT_5G_FEATURES"
#define UPF_CONFIG_STRING_ENABLE_5G_FEATURES "ENABLE_5G_FEATURES"
#define UPF_CONFIG_STRING_5G_FEATURES_REGISTER_NRF "REGISTER_NRF"
#define UPF_CONFIG_STRING_5G_FEATURES_UPF_FQDN "UPF_FQDN_5G"
#define UPF_CONFIG_STRING_5G_FEATURES_NRF "NRF"
#define UPF_CONFIG_STRING_5G_FEATURES_NRF_IPV4_ADDRESS "IPV4_ADDRESS"
#define UPF_CONFIG_STRING_5G_FEATURES_NRF_PORT "PORT"
#define UPF_CONFIG_STRING_5G_FEATURES_NRF_HTTP_VERSION "HTTP_VERSION"
#define UPF_CONFIG_STRING_5G_FEATURES_NRF_API_VERSION "API_VERSION"
#define UPF_CONFIG_STRING_5G_FEATURES_UPF_INFO "UPF_INFO"
#define UPF_CONFIG_STRING_5G_FEATURES_NSSAI_SST "NSSAI_SST"
#define UPF_CONFIG_STRING_5G_FEATURES_NSSAI_SD "NSSAI_SD"
#define UPF_CONFIG_STRING_5G_FEATURES_DNN "DNN"
#define UPF_CONFIG_STRING_5G_FEATURES_USE_FQDN_NRF "USE_FQDN_NRF"
#define UPF_CONFIG_STRING_5G_FEATURES_UPF_INFO_DNN_LIST "DNN_LIST"

#define UPF_ABORT_ON_ERROR true
#define UPG_WARN_ON_ERROR false

typedef struct interface_cfg_s {
  std::string if_name;
  struct in_addr addr4;
  struct in_addr network4;
  struct in6_addr addr6;
  unsigned int mtu;
  unsigned int port;
  util::thread_sched_params thread_rd_sched_params;
} interface_cfg_t;

typedef struct pdn_cfg_s {
  struct in_addr network_ipv4;
  uint32_t network_ipv4_be;
  uint32_t network_mask_ipv4;
  uint32_t network_mask_ipv4_be;
  int prefix_ipv4;
  struct in6_addr network_ipv6;
  int prefix_ipv6;
} pdn_cfg_t;

typedef struct itti_cfg_s {
  util::thread_sched_params itti_timer_sched_params;
  util::thread_sched_params s1u_sched_params;
  util::thread_sched_params sx_sched_params;
  util::thread_sched_params upf_app_sched_params;
  util::thread_sched_params async_cmd_sched_params;
} itti_cfg_t;

// Non standart features
typedef struct nsf_cfg_s {
  bool bypass_ul_pfcp_rules;
} nsf_cfg_t;
class upf_config {
 private:
  int load_itti(const libconfig::Setting& itti_cfg, itti_cfg_t& cfg);
  int load_interface(const libconfig::Setting& if_cfg, interface_cfg_t& cfg);
  int load_thread_sched_params(
      const libconfig::Setting& thread_sched_params_cfg,
      util::thread_sched_params& cfg);

 public:
  /* Reader/writer lock for this configuration */
  std::mutex m_rw_lock;
  std::string pid_dir;
  unsigned int instance;
  std::string fqdn;
  interface_cfg_t n3;
  interface_cfg_t n6;
  interface_cfg_t n4;
  itti_cfg_t itti;
  nsf_cfg_t nsf;

  std::string gateway;

  uint32_t max_pfcp_sessions;

  bool snat;
  std::vector<pdn_cfg_t> pdns;
  std::vector<pfcp::node_id_t> smfs;

  struct {
    bool enable_5g_features;
    bool register_nrf;
    upf_info_t upf_info;
    bool use_fqdn_nrf;
    struct {
      struct in_addr ipv4_addr;
      unsigned int port;
      unsigned int http_version;
      std::string api_version;
      std::string fqdn;
    } nrf_addr;
  } upf_5g_features;

  upf_config()
      : m_rw_lock(),
        pid_dir(),
        instance(0),
        fqdn(),
        n3(),
        n6(),
        gateway(),
        n4(),
        itti(),
        pdns(),
        smfs(),
        max_pfcp_sessions(100),
        nsf(),
        snat(false) {
    itti.itti_timer_sched_params.sched_priority = 85;
    itti.s1u_sched_params.sched_priority        = 84;
    itti.sx_sched_params.sched_priority         = 84;
    itti.upf_app_sched_params.sched_priority    = 84;
    itti.async_cmd_sched_params.sched_priority  = 84;

    n3.thread_rd_sched_params.sched_priority = 98;
    n3.port                                  = gtpv1u::default_port;

    n6.thread_rd_sched_params.sched_priority = 98;

    n4.thread_rd_sched_params.sched_priority = 95;
    n4.port                                  = pfcp::default_port;

    upf_5g_features.enable_5g_features        = false;
    upf_5g_features.register_nrf              = false;
    upf_5g_features.upf_info                  = {};
    upf_5g_features.use_fqdn_nrf              = false;
    upf_5g_features.nrf_addr.ipv4_addr.s_addr = INADDR_ANY;
    upf_5g_features.nrf_addr.port             = 80;
    upf_5g_features.nrf_addr.api_version      = "v1";
    upf_5g_features.nrf_addr.fqdn             = {};
  };

  void lock() { m_rw_lock.lock(); };
  void unlock() { m_rw_lock.unlock(); };
  int load(const std::string& config_file);
  int execute();
  void display();
  int get_pfcp_node_id(pfcp::node_id_t& node_id);
  int get_pfcp_fseid(pfcp::fseid_t& fseid);
};
}  // namespace upf

#endif /* FILE_UPF_CONFIG_HPP_SEEN */
