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

/*! \file simple_switch.cpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/
#include "3gpp_conversions.hpp"
#include "common_defs.h"
#include "conversions.hpp"
#include "gtpu.h"
#include "itti.hpp"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "upf_config.hpp"
#include "simple_switch.hpp"

#include <stdexcept>

using namespace gtpv1u;
using namespace upf;
using namespace std;

extern itti_mw* itti_inst;
extern pfcp_switch* pfcp_switch_inst;
extern upf_config upf_cfg;
extern upf_n3* upf_n3_inst;

void upf_n3_task(void*);

//------------------------------------------------------------------------------

void upf_n3_task(void* args_p) {
  const task_id_t task_id = TASK_UPF_N3;

  const util::thread_sched_params* const sched_params =
      (const util::thread_sched_params* const) args_p;
  sched_params->apply(task_id, Logger::upf_n3());

  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case S1U_ECHO_RESPONSE:
        upf_n3_inst->handle_itti_msg(
            std::static_pointer_cast<itti_s1u_echo_response>(shared_msg));
        break;

      case S1U_ERROR_INDICATION:
        upf_n3_inst->handle_itti_msg(
            std::static_pointer_cast<itti_s1u_error_indication>(shared_msg));
        break;

      case TIME_OUT:
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          Logger::upf_n3().info("TIME-OUT event timer id %d", to->timer_id);
        }
        break;

      case TERMINATE:
        if (itti_msg_terminate* terminate =
                dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::upf_n3().info("Received terminate message");
          upf_n3_inst->stop();
          return;
        }
        break;

      case HEALTH_PING:
        break;

      default:
        Logger::upf_n3().info("no handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
upf_n3::upf_n3()
    : gtpu_l4_stack(
          upf_cfg.n3.addr4, upf_cfg.n3.port, upf_cfg.n3.thread_rd_sched_params,
          upf_cfg.upf_5g_features.enable_5g_features) {
  Logger::upf_n3().startup("Starting...");
  if (itti_inst->create_task(
          TASK_UPF_N3, upf_n3_task, &upf_cfg.itti.s1u_sched_params)) {
    Logger::upf_n3().error("Cannot create task TASK_UPF_N3");
    throw std::runtime_error("Cannot create task TASK_UPF_N3");
  }
  Logger::upf_n3().startup("Started");
}
//------------------------------------------------------------------------------
void upf_n3::handle_receive(
    char* recv_buffer, const std::size_t bytes_transferred,
    const endpoint& r_endpoint) {
#define GTPU_MESSAGE_FLAGS_POS_IN_UDP_PAYLOAD 0
  // auto start = std::chrono::high_resolution_clock::now();
  struct gtpuhdr* gtpuh = (struct gtpuhdr*) &recv_buffer[0];

  if (gtpuh->version == 1) {
    // Do it fast, do not go throught handle_receive_gtpv1u_msg()
    if (gtpuh->message_type == GTPU_G_PDU) {
      uint8_t gtp_flags = recv_buffer[GTPU_MESSAGE_FLAGS_POS_IN_UDP_PAYLOAD];
      std::size_t gtp_payload_offset = GTPV1U_MSG_HEADER_MIN_SIZE;
      if ((((gtp_flags & GTPU_MESSAGE_VERSION_MASK)) &&
           (gtp_flags & GTPU_MESSAGE_PT_MASK)) &&
          ((gtp_flags & GTPU_MESSAGE_EXT_HEADER_MASK) ||
           (gtp_flags & GTPU_MESSAGE_SN_MASK) ||
           (gtp_flags & GTPU_MESSAGE_PN_MASK)))
        gtp_payload_offset += 4;
      std::size_t gtp_payload_length = be16toh(gtpuh->message_length);
      if (gtp_flags & 0x07) {
        gtp_payload_offset += 4;
        gtp_payload_length -= 4;
      }
      uint32_t tunnel_id = be32toh(gtpuh->teid);

      struct iphdr* iph = (struct iphdr*) &recv_buffer[gtp_payload_offset];
      if (iph->version == 4) {
        pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
            iph, gtp_payload_length, r_endpoint, tunnel_id);
      } else if (iph->version == 6) {
        pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
            (struct ipv6hdr*) iph, gtp_payload_length, r_endpoint, tunnel_id);
      } else {
        Logger::upf_n3().trace("Unknown GTPU_G_PDU packet");
      }
    } else {
      // Logger::upf_n3().info( "handle_receive(%d bytes)",
      // bytes_transferred); std::cout << string_to_hex(recv_buffer,
      // bytes_transferred) << std::endl;
      std::istringstream iss(std::istringstream::binary);
      iss.rdbuf()->pubsetbuf(recv_buffer, bytes_transferred);
      gtpv1u_msg msg = {};
      try {
        msg.load_from(iss);
        handle_receive_gtpv1u_msg(msg, r_endpoint);
      } catch (gtpu_exception& e) {
        Logger::upf_n3().info("handle_receive exception %s", e.what());
      }
    }
  } else {
    struct iphdr* iph = (struct iphdr*) &recv_buffer[0];
    if (iph->version == 4) {
      pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
          iph, bytes_transferred, r_endpoint);
    } else if (iph->version == 6) {
      pfcp_switch_inst->pfcp_session_look_up_pack_in_access(
          (struct ipv6hdr*) iph, bytes_transferred, r_endpoint);
    } else {
      Logger::upf_n3().trace("Unknown IPX packet");
    }
  }
  // auto stop = std::chrono::high_resolution_clock::now();
  // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop
  // - start); cout << "UL took "  << duration.count() << std::endl;
}
//------------------------------------------------------------------------------
void upf_n3::handle_receive_gtpv1u_msg(
    gtpv1u_msg& msg, const endpoint& r_endpoint) {
  // Logger::upf_n3().trace( "handle_receive_gtpv1u_msg msg type %d length
  // %d", msg.get_message_type(), msg.get_message_length());
  switch (msg.get_message_type()) {
    case GTPU_ECHO_REQUEST:
      handle_receive_echo_request(msg, r_endpoint);
      break;
    case GTPU_ECHO_RESPONSE:
    case GTPU_ERROR_INDICATION:
    case GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION:
    case GTPU_END_MARKER:
    case GTPU_G_PDU:
      break;
    default:
      Logger::upf_n3().error(
          "handle_receive_gtpv1u_msg msg length %d", msg.get_message_length());
  }
}
//------------------------------------------------------------------------------
void upf_n3::send_g_pdu(
    const struct in_addr& peer_addr, const uint16_t peer_udp_port,
    const uint32_t tunnel_id, const char* send_buffer, const ssize_t num_bytes,
    uint8_t qfi) {
  // Logger::upf_n3().info( "upf_n3::send_g_pdu() TEID " TEID_FMT " %d
  // bytes", num_bytes);
  struct sockaddr_in peer_sock_addr;
  peer_sock_addr.sin_family = AF_INET;
  peer_sock_addr.sin_addr   = peer_addr;
  peer_sock_addr.sin_port   = htobe16(peer_udp_port);
  gtpu_l4_stack::send_g_pdu(
      peer_sock_addr, (teid_t) tunnel_id, send_buffer, num_bytes, qfi);
}
//------------------------------------------------------------------------------
void upf_n3::send_g_pdu(
    const struct in6_addr& peer_addr, const uint16_t peer_udp_port,
    const uint32_t tunnel_id, const char* send_buffer,
    const ssize_t num_bytes) {
  struct sockaddr_in6 peer_sock_addr;
  peer_sock_addr.sin6_family   = AF_INET6;
  peer_sock_addr.sin6_addr     = peer_addr;
  peer_sock_addr.sin6_port     = htobe16(peer_udp_port);
  peer_sock_addr.sin6_flowinfo = 0;
  peer_sock_addr.sin6_scope_id = 0;
  gtpu_l4_stack::send_g_pdu(peer_sock_addr, tunnel_id, send_buffer, num_bytes);
}
//------------------------------------------------------------------------------
void upf_n3::handle_receive_echo_request(
    gtpv1u_msg& msg, const endpoint& r_endpoint) {
  itti_s1u_echo_request* echo =
      new itti_s1u_echo_request(TASK_UPF_N3, TASK_UPF_APP);

  gtpv1u_echo_request msg_ies_container = {};
  msg.to_core_type(echo->gtp_ies);

  echo->gtp_ies.r_endpoint = r_endpoint;
  echo->gtp_ies.set_teid(msg.get_teid());

  uint16_t sn = 0;
  if (msg.get_sequence_number(sn)) {
    echo->gtp_ies.set_sequence_number(sn);
  }

  std::shared_ptr<itti_s1u_echo_request> secho =
      std::shared_ptr<itti_s1u_echo_request>(echo);
  int ret = itti_inst->send_msg(secho);
  if (RETURNok != ret) {
    Logger::upf_n3().error(
        "Could not send ITTI message %s to task TASK_UPF_APP",
        echo->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void upf_n3::handle_itti_msg(std::shared_ptr<itti_s1u_echo_response> m) {
  send_response(m->gtp_ies);
}
//------------------------------------------------------------------------------
void upf_n3::handle_itti_msg(std::shared_ptr<itti_s1u_error_indication> m) {
  send_indication(m->gtp_ies);
}
//------------------------------------------------------------------------------
void upf_n3::report_error_indication(
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  itti_s1u_error_indication* error_ind =
      new itti_s1u_error_indication(TASK_UPF_N3, TASK_UPF_N3);
  error_ind->gtp_ies.r_endpoint = r_endpoint;
  error_ind->gtp_ies.set_teid(0);

  tunnel_endpoint_identifier_data_i_t tun_data = {};
  tun_data.tunnel_endpoint_identifier_data_i   = tunnel_id;
  error_ind->gtp_ies.set(tun_data);

  gtp_u_peer_address_t peer_address = {};
  if (xgpp_conv::endpoint_to_gtp_u_peer_address(r_endpoint, peer_address)) {
    error_ind->gtp_ies.set(peer_address);
  } else {
    // mandatory ie
    delete error_ind;
    return;
  }

  std::shared_ptr<itti_s1u_error_indication> serror_ind =
      std::shared_ptr<itti_s1u_error_indication>(error_ind);
  int ret = itti_inst->send_msg(serror_ind);
  if (RETURNok != ret) {
    Logger::upf_n3().error(
        "Could not send ITTI message %s to task TASK_UPF_N3",
        error_ind->get_msg_name());
  }
}
