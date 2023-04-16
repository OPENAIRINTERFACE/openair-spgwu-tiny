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

/*! \file upf_app.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#include "conversions.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_app.hpp"
#include "upf_config.hpp"
#include "simple_switch.hpp"
#include "upf_n4.hpp"
#include "upf_nrf.hpp"

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <stdexcept>

using namespace pfcp;
using namespace upf;
using namespace std;

// C includes

upf_n4* upf_n4_inst   = nullptr;
upf_n3* upf_n3_inst   = nullptr;
upf_nrf* upf_nrf_inst = nullptr;

extern itti_mw* itti_inst;
extern pfcp_switch* pfcp_switch_inst;
extern upf_app* upf_app_inst;
extern upf_config upf_cfg;

void upf_app_task(void*);

//------------------------------------------------------------------------------
void upf_app_task(void* args_p) {
  const task_id_t task_id = TASK_UPF_APP;

  const util::thread_sched_params* const sched_params =
      (const util::thread_sched_params* const) args_p;

  sched_params->apply(task_id, Logger::upf_app());

  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case S1U_ECHO_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_s1u_echo_request>(shared_msg));
        break;

      case N4_SESSION_ESTABLISHMENT_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_establishment_request>(
                shared_msg));
        break;

      case N4_SESSION_MODIFICATION_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_modification_request>(
                shared_msg));
        break;

      case N4_SESSION_DELETION_REQUEST:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_deletion_request>(
                shared_msg));
        break;

      case N4_SESSION_REPORT_RESPONSE:
        upf_app_inst->handle_itti_msg(
            std::static_pointer_cast<itti_n4_session_report_response>(
                shared_msg));
        break;

      case TIME_OUT:
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          switch (to->arg1_user) {
            case TASK_UPF_PFCP_SWITCH_MIN_COMMIT_INTERVAL:
              // pfcp_switch_inst->time_out_min_commit_interval(to->timer_id);
              break;
            case TASK_UPF_PFCP_SWITCH_MAX_COMMIT_INTERVAL:
              // pfcp_switch_inst->time_out_max_commit_interval(to->timer_id);
              break;
            default:;
          }
        }
        break;

      case TERMINATE:
        if (itti_msg_terminate* terminate =
                dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::upf_app().info("Received terminate message");
          return;
        }
        break;

      case HEALTH_PING:
        break;

      default:
        Logger::upf_app().info(
            "no handler for ITTI msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
upf_app::upf_app(const std::string& config_file) {
  Logger::upf_app().startup("Starting...");
  upf_cfg.execute();

  if (itti_inst->create_task(
          TASK_UPF_APP, upf_app_task, &upf_cfg.itti.upf_app_sched_params)) {
    Logger::upf_app().error("Cannot create task TASK_UPF_APP");
    throw std::runtime_error("Cannot create task TASK_UPF_APP");
  }
  try {
    upf_n4_inst = new upf_n4();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create UPF_N4: %s", e.what());
    throw;
  }
  try {
    upf_n3_inst = new upf_n3();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create UPF_N3: %s", e.what());
    throw;
  }
  try {
    pfcp_switch_inst = new pfcp_switch();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create PFCP_SWITCH: %s", e.what());
    throw;
  }
  try {
    if (upf_cfg.upf_5g_features.enable_5g_features and
        upf_cfg.upf_5g_features.register_nrf)
      upf_nrf_inst = new upf_nrf();
  } catch (std::exception& e) {
    Logger::upf_app().error("Cannot create UPF_NRF: %s", e.what());
    throw;
  }
  Logger::upf_app().startup("Started");
}

//------------------------------------------------------------------------------
upf_app::~upf_app() {
  if (upf_n4_inst) delete upf_n4_inst;
  if (upf_nrf_inst) delete upf_nrf_inst;
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(std::shared_ptr<itti_s1u_echo_request> m) {
  Logger::upf_app().debug("Received %s ", m->get_msg_name());
  itti_s1u_echo_response* s1u_resp =
      new itti_s1u_echo_response(TASK_UPF_APP, TASK_UPF_N3);

  // May insert a call to a function here(throttle for example)
  s1u_resp->gtp_ies.r_endpoint      = m->gtp_ies.r_endpoint;
  s1u_resp->gtp_ies.teid            = m->gtp_ies.teid;
  s1u_resp->gtp_ies.sequence_number = m->gtp_ies.sequence_number;

  std::shared_ptr<itti_s1u_echo_response> msg =
      std::shared_ptr<itti_s1u_echo_response>(s1u_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N3",
        s1u_resp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_establishment_request> m) {
  Logger::upf_app().info(
      "Received N4_SESSION_ESTABLISHMENT_REQUEST seid " SEID_FMT " ", m->seid);
  itti_n4_session_establishment_response* n4_resp =
      new itti_n4_session_establishment_response(TASK_UPF_APP, TASK_UPF_N4);
  pfcp_switch_inst->handle_pfcp_session_establishment_request(m, n4_resp);

  pfcp::node_id_t node_id = {};
  upf_cfg.get_pfcp_node_id(node_id);
  n4_resp->pfcp_ies.set(node_id);

  n4_resp->trxn_id = m->trxn_id;
  n4_resp->seid    = m->pfcp_ies.cp_fseid.second
                      .seid;  // Mandatory IE, but... may be bad to do this
  n4_resp->r_endpoint = m->r_endpoint;
  n4_resp->l_endpoint = m->l_endpoint;
  std::shared_ptr<itti_n4_session_establishment_response> msg =
      std::shared_ptr<itti_n4_session_establishment_response>(n4_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N4",
        n4_resp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_modification_request> m) {
  Logger::upf_app().info(
      "Received N4_SESSION_MODIFICATION_REQUEST seid " SEID_FMT " ", m->seid);
  itti_n4_session_modification_response* n4_resp =
      new itti_n4_session_modification_response(TASK_UPF_APP, TASK_UPF_N4);
  pfcp_switch_inst->handle_pfcp_session_modification_request(m, n4_resp);

  n4_resp->trxn_id    = m->trxn_id;
  n4_resp->r_endpoint = m->r_endpoint;
  n4_resp->l_endpoint = m->l_endpoint;
  std::shared_ptr<itti_n4_session_modification_response> msg =
      std::shared_ptr<itti_n4_session_modification_response>(n4_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N4",
        n4_resp->get_msg_name());
  }
}
//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_deletion_request> m) {
  Logger::upf_app().info(
      "Received N4_SESSION_DELETION_REQUEST seid " SEID_FMT " ", m->seid);
  itti_n4_session_deletion_response* n4_resp =
      new itti_n4_session_deletion_response(TASK_UPF_APP, TASK_UPF_N4);
  pfcp_switch_inst->handle_pfcp_session_deletion_request(m, n4_resp);

  n4_resp->trxn_id    = m->trxn_id;
  n4_resp->r_endpoint = m->r_endpoint;
  n4_resp->l_endpoint = m->l_endpoint;
  std::shared_ptr<itti_n4_session_deletion_response> msg =
      std::shared_ptr<itti_n4_session_deletion_response>(n4_resp);
  int ret = itti_inst->send_msg(msg);
  if (RETURNok != ret) {
    Logger::upf_app().error(
        "Could not send ITTI message %s to task TASK_UPF_N4",
        n4_resp->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void upf_app::handle_itti_msg(
    std::shared_ptr<itti_n4_session_report_response> m) {
  Logger::upf_app().info(
      "Received N4_SESSION_REPORT_RESPONSE seid " SEID_FMT " ", m->seid);
}
