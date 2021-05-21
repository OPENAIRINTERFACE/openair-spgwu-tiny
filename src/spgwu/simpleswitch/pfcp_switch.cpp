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

/*! \file pfcp_switch.cpp
  \brief
  \author Lionel Gauthier
  \date 2019
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "common_defs.h"
#include "itti.hpp"
#include "logger.hpp"
#include "pfcp_switch.hpp"
#include "spgwu_config.hpp"
#include "spgwu_pfcp_association.hpp"
#include "spgwu_s1u.hpp"

#include <algorithm>
#include <fstream>  // std::ifstream
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/ip.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <stdexcept>
#include <net/ethernet.h>

using namespace pfcp;
using namespace gtpv1u;
using namespace spgwu;
using namespace std;

extern itti_mw* itti_inst;
extern spgwu_config spgwu_cfg;
extern spgwu_s1u* spgwu_s1u_inst;
extern pfcp_switch* pfcp_switch_inst;

//------------------------------------------------------------------------------
void pfcp_switch::pdn_worker(
    const int id, const util::thread_sched_params& sched_params) {
  uint64_t count      = 0;
  iovec_q_item_t* iov = nullptr;

  sched_params.apply(TASK_NONE, Logger::udp());
  while (1) {
    work_pool_->blockingRead(iov);
    ++count;
    // std::cout << "DL worker " << id << " count " << count << std::endl;
    // exit thread
    if (iov->msg_iov.iov_base) {
      pfcp_session_look_up_pack_in_core(
          (const char*) iov->msg_iov.iov_base, iov->msg_iov.iov_len);
      free_pool_->write(iov);
    } else {
      free(iov);
      std::cout << "exit DL w" << id << " " << count << std::endl;
      while (work_pool_->readIfNotEmpty(iov)) {
        free(iov);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      }
      return;
    }
    iov = nullptr;
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::pdn_read_loop(
    int sock_r, const util::thread_sched_params& sched_params) {
  uint64_t count      = 0;
  uint64_t errors     = 0;
  iovec_q_item_t* iov = nullptr;
  // struct sockaddr_in   sin = {};

  sched_params.apply(TASK_NONE, Logger::pfcp_switch());

  while (1) {
    if (!iov) {
      free_pool_->blockingRead(iov);
    }
    // iov->msg.msg_name = &sin;
    // iov->msg.msg_namelen = sizeof(sin);
    // iov->msg.msg_iovlen = 1;
    // iov->msg.msg_flags = 0;
    iov->msg_iov.iov_len = PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU;
    // iov->msg.msg_control = nullptr;      /* Set to NULL if not needed  */
    // iov->msg.msg_controllen = 0;
    // exit thread
    if (iov->msg_iov.iov_base == nullptr) {
      free(iov);
      while (work_pool_->readIfNotEmpty(iov)) {
        free(iov);
      }
      std::cout << "exit d" << count << std::endl;
      return;
    }
    ssize_t nread;
    if ((nread = read(sock_r, iov->msg_iov.iov_base, iov->msg_iov.iov_len)) >
        0) {
      ++count;
      // std::cout << "pdn" << count << " " << nread << " bytes" << std::endl;
      iov->msg_iov.iov_len = nread;
      work_pool_->write(iov);
      iov = nullptr;
    } else {
      ++errors;
      Logger::pfcp_switch().error(
          "recvmsg failed rc=%d:%s nb_errors %d", nread, strerror(errno),
          errors);
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      exit(0);
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::send_to_core(char* const ip_packet, const ssize_t len) {
  ssize_t bytes_sent;
  // Logger::pfcp_switch().trace( "pfcp_switch::send_to_core %d bytes ", len);
  if ((bytes_sent = write(sock_w, ip_packet, len)) < 0) {
    Logger::pfcp_switch().error(
        "write fd %d failed rc=%d:%s", sock_w, bytes_sent, strerror(errno));
  }
}
//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket(
    const char* const ifname, const bool promisc, int& if_index) {
  struct sockaddr_in addr = {};
  int sd                  = 0;

  /*
   * Create socket
   * The  socket_type is either SOCK_RAW for raw packets including the
   * link-level header or SOCK_DGRAM for cooked packets with the link-level
   * header removed.
   */

  if ((sd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) < 0) {
    /*
     * Socket creation has failed...
     */
    Logger::pfcp_switch().error("Socket creation failed (%s)", strerror(errno));
    return RETURNerror;
  }

  if (ifname) {
    struct ifreq ifr = {};
    strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
      Logger::pfcp_switch().error(
          "Get interface index failed (%s) for %s", strerror(errno), ifname);
      close(sd);
      return RETURNerror;
    }

    if_index = ifr.ifr_ifindex;

    struct sockaddr_ll sll = {};
    sll.sll_family         = AF_PACKET;        /* Always AF_PACKET */
    sll.sll_protocol       = htons(ETH_P_ALL); /* Physical-layer protocol */
    sll.sll_ifindex        = ifr.ifr_ifindex;  /* Interface number */
    sll.sll_pkttype        = PACKET_HOST;
    if (bind(sd, (struct sockaddr*) &sll, sizeof(sll)) < 0) {
      /*
       * Bind failed
       */
      Logger::pfcp_switch().error(
          "Socket bind to %s failed (%s)", ifname, strerror(errno));
      close(sd);
      return RETURNerror;
    }

    if (promisc) {
      struct packet_mreq mreq = {};
      mreq.mr_ifindex         = if_index;
      mreq.mr_type            = PACKET_MR_PROMISC;
      if (setsockopt(
              sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        Logger::pfcp_switch().error(
            "Set promiscuous mode failed (%s)", strerror(errno));
        close(sd);
        return RETURNerror;
      }
    }
  }
  return sd;
}
//------------------------------------------------------------------------------
int pfcp_switch::create_pdn_socket(const char* const ifname) {
  struct sockaddr_in addr = {};
  int sd                  = RETURNerror;

  if (ifname) {
    /*
     * Create socket
     * The  socket_type is either SOCK_RAW for raw packets including the
     * link-level header or SOCK_DGRAM for cooked packets with the link-level
     * header removed.
     */
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
      /*
       * Socket creation has failed...
       */
      Logger::pfcp_switch().error(
          "Socket creation failed (%s)", strerror(errno));
      return RETURNerror;
    }

    int option_on          = 1;
    const int* p_option_on = &option_on;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, p_option_on, sizeof(option_on)) <
        0) {
      Logger::pfcp_switch().error(
          "Set header included failed (%s)", strerror(errno));
      close(sd);
      return RETURNerror;
    }

    struct ifreq ifr = {};
    strncpy((char*) ifr.ifr_name, ifname, IFNAMSIZ);
    if ((setsockopt(
            sd, SOL_SOCKET, SO_BINDTODEVICE, (void*) &ifr, sizeof(ifr))) < 0) {
      Logger::pfcp_switch().error(
          "Socket bind to %s failed (%s)", ifname, strerror(errno));
      close(sd);
      return RETURNerror;
    }
    return sd;
  }
  return RETURNerror;
}
//------------------------------------------------------------------------------
int pfcp_switch::tun_open(char* devname, int flags) {
  struct ifreq ifr;
  int fd, err;
  if ((fd = open("/dev/net/tun", flags)) == -1) {
    Logger::pfcp_switch().error("open /dev/net/tun");
    return RETURNerror;
  }
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, devname, IFNAMSIZ);  // devname = tunX

  if ((err = ioctl(fd, TUNSETIFF, (void*) &ifr)) == -1) {
    Logger::pfcp_switch().error("ioctl TUNSETIFF %d %s", err, strerror(errno));
    close(fd);
    return RETURNerror;
  }
  return fd;
}
//------------------------------------------------------------------------------
void pfcp_switch::setup_pdn_interfaces() {
  std::string cmd = {};
  int rc          = 0;
  int if_index    = 0;

  int index = 0;
  // TODO for loop on pdns
  {
    pdn_cfg_t it = spgwu_cfg.pdns[index];
    int sock_r   = 0;

    cmd = fmt::format("ip tuntap add mode tun dev tun{}", index);
    rc  = system((const char*) cmd.c_str());

    cmd = fmt::format("ip link set dev tun{} up", index);
    rc  = system((const char*) cmd.c_str());

    cmd = fmt::format("ethtool -K tun{0} tx-checksum-ip-generic off;", index);
    rc  = system((const char*) cmd.c_str());
    if (it.prefix_ipv4) {
      struct in_addr address4 = {};
      address4.s_addr         = it.network_ipv4.s_addr + be32toh(1);

      cmd = fmt::format(
          "ip addr add {}/{} dev tun{}", conv::toString(address4).c_str(),
          it.prefix_ipv4, index);
      rc = system((const char*) cmd.c_str());

      if (spgwu_cfg.snat) {
        cmd = fmt::format(
            "iptables -t nat -A POSTROUTING -s {}/{} -o {} -j SNAT --to-source "
            "{}",
            conv::toString(it.network_ipv4).c_str(), it.prefix_ipv4,
            spgwu_cfg.sgi.if_name.c_str(),
            conv::toString(spgwu_cfg.sgi.addr4).c_str());
        rc = system((const char*) cmd.c_str());
      }
    }
    if (it.prefix_ipv6) {
      std::string cmd = fmt::format(
          "echo 0 > /proc/sys/net/ipv6/conf/tun{}/disable_ipv6", index);
      rc = system((const char*) cmd.c_str());

      struct in6_addr addr6 = it.network_ipv6;
      addr6.s6_addr[15]     = 1;
      cmd                   = fmt::format(
          "ip -6 addr add {}/{} dev tun{}", conv::toString(addr6).c_str(),
          it.prefix_ipv6, index);
      rc = system((const char*) cmd.c_str());
      // if ((it.snat) && (/* SGI has IPv6 address*/)){
      //    cmd = fmt::format("ip6tables -t nat -A POSTROUTING -s {}/{} -o {} -j
      //    SNAT --to-source {}", conv::toString(addr6).c_str(), it.prefix_ipv6,
      //    xxx); rc = system ((const char*)cmd.c_str());
      //}
    }
    // even if we do nat, we can receive ue ip destinated IP packet
    // but do not forget to set routes outside SPGWu
    cmd = fmt::format(
        "/sbin/sysctl -w net.ipv4.conf.{}.rp_filter=0",
        spgwu_cfg.sgi.if_name.c_str());
    rc = system((const char*) cmd.c_str());

    // Otherwise redirect incoming ingress UE IP to default gw
    // cmd = fmt::format("/sbin/sysctl -w net.ipv4.conf.tun{}.send_redirects=0",
    // index); rc = system ((const char*)cmd.c_str()); cmd =
    // fmt::format("/sbin/sysctl -w net.ipv4.conf.tun{}.accept_redirects=0",
    // index); rc = system ((const char*)cmd.c_str());

    cmd = fmt::format("tun{}", index);
    if ((sock_r = tun_open((char*) cmd.c_str(), O_RDWR)) == RETURNerror) {
      Logger::pfcp_switch().error("Could not set PDN interface read socket");
      sleep(2);
      exit(EXIT_FAILURE);
    }

    sock_w = sock_r;

    std::thread t = thread(
        &pfcp_switch::pdn_read_loop, this, sock_r,
        spgwu_cfg.sgi.thread_rd_sched_params);
    t.detach();
    threads_.push_back(std::move(t));
    socks_r.push_back(sock_r);
  }

  rc = system("/sbin/sysctl -w net.ipv4.conf.all.forwarding=1");
  rc = system("/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0");
  rc = system("/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0");
  rc = system("/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0");
  rc = system("/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0");
}

//------------------------------------------------------------------------------
pfcp::fteid_t pfcp_switch::generate_fteid_s1u() {
  pfcp::fteid_t fteid = {};
  fteid.teid          = generate_teid_s1u();
  if (spgwu_cfg.s1_up.addr4.s_addr) {
    fteid.v4                  = 1;
    fteid.ipv4_address.s_addr = spgwu_cfg.s1_up.addr4.s_addr;
  } else {
    fteid.v6           = 1;
    fteid.ipv6_address = spgwu_cfg.s1_up.addr6;
  }
  return fteid;
}
//------------------------------------------------------------------------------
pfcp_switch::pfcp_switch()
    : seid_generator_(),
      teid_s1u_generator_(),
      ue_ipv4_hbo2pfcp_pdr(PFCP_SWITCH_MAX_PDRS),
      ul_s1u_teid2pfcp_pdr(PFCP_SWITCH_MAX_PDRS),
      up_seid2pfcp_sessions(PFCP_SWITCH_MAX_SESSIONS),
      threads_(16),
      socks_r(16),
      sock_w(0) {
  num_threads_   = 8;
  int num_blocks = num_threads_ * 16;
  free_pool_     = new folly::MPMCQueue<iovec_q_item_t*>(num_blocks);
  work_pool_     = new folly::MPMCQueue<iovec_q_item_t*>(num_blocks);

  recv_buffer_alloc_ = (char*) calloc(num_blocks, PFCP_SWITCH_RECV_BUFFER_SIZE);

  for (int i = 0; i < num_blocks; i++) {
    iovec_q_item_s* v = (iovec_q_item_s*) calloc(1, sizeof(iovec_q_item_s));
    v->msg_iov.iov_base =
        (void*) ((uintptr_t) calloc(1, PFCP_SWITCH_RECV_BUFFER_SIZE) + (uintptr_t) ROOM_FOR_GTPV1U_G_PDU);
    v->msg_iov.iov_len = PFCP_SWITCH_RECV_BUFFER_SIZE - ROOM_FOR_GTPV1U_G_PDU;
    v->msg.msg_iovlen  = 1;
    v->msg.msg_flags   = 0;
    v->msg.msg_control = nullptr;
    v->msg.msg_controllen = 0;
    free_pool_->blockingWrite(v);
  }
  for (int i = 0; i < num_threads_; i++) {
    std::thread t = std::thread(
        &pfcp_switch::pdn_worker, this, i,
        spgwu_cfg.sgi.thread_rd_sched_params);
    threads_.push_back(std::move(t));
  }
  timer_min_commit_interval_id = 0;
  timer_max_commit_interval_id = 0;
  cp_fseid2pfcp_sessions = {}, sock_w = -1;
  pdn_if_index = -1;
  setup_pdn_interfaces();
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_cp_fseid(
    const pfcp::fseid_t& fseid,
    std::shared_ptr<pfcp::pfcp_session>& session) const {
  std::unordered_map<
      fseid_t, std::shared_ptr<pfcp::pfcp_session>>::const_iterator sit =
      cp_fseid2pfcp_sessions.find(fseid);
  if (sit == cp_fseid2pfcp_sessions.end()) {
    return false;
  } else {
    session = sit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_session_by_up_seid(
    const uint64_t cp_seid,
    std::shared_ptr<pfcp::pfcp_session>& session) const {
  folly::AtomicHashMap<
      uint64_t, std::shared_ptr<pfcp::pfcp_session>>::const_iterator sit =
      up_seid2pfcp_sessions.find(cp_seid);
  if (sit == up_seid2pfcp_sessions.end()) {
    return false;
  } else {
    session = sit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_ul_pdrs_by_up_teid(
    const teid_t teid,
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const {
  folly::AtomicHashMap<
      teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::
      const_iterator pit = ul_s1u_teid2pfcp_pdr.find(teid);
  if (pit == ul_s1u_teid2pfcp_pdr.end())
    return false;
  else {
    pdrs = pit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::get_pfcp_dl_pdrs_by_ue_ip(
    const uint32_t ue_ip,
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>& pdrs) const {
  folly::AtomicHashMap<
      uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::
      const_iterator pit = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
  if (pit == ue_ipv4_hbo2pfcp_pdr.end())
    return false;
  else {
    pdrs = pit->second;
    return true;
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_cp_fseid(
    const pfcp::fseid_t& fseid, std::shared_ptr<pfcp::pfcp_session>& session) {
  std::pair<fseid_t, std::shared_ptr<pfcp::pfcp_session>> entry(fseid, session);
  cp_fseid2pfcp_sessions.insert(entry);
}
//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_session_by_up_seid(
    const uint64_t seid, std::shared_ptr<pfcp::pfcp_session>& session) {
  std::pair<uint64_t, std::shared_ptr<pfcp::pfcp_session>> entry(seid, session);
  up_seid2pfcp_sessions.insert(entry);
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(
    std::shared_ptr<pfcp::pfcp_session>& session) {
  session->cleanup();
  cp_fseid2pfcp_sessions.erase(session->cp_fseid);
  up_seid2pfcp_sessions.erase(session->seid);
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_session(const pfcp::fseid_t& cp_fseid) {
  std::shared_ptr<pfcp::pfcp_session> session = {};
  if (get_pfcp_session_by_cp_fseid(cp_fseid, session)) {
    remove_pfcp_session(session);
  }
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_ul_pdr_by_up_teid(
    const teid_t teid, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  folly::AtomicHashMap<
      teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::
      const_iterator pit = ul_s1u_teid2pfcp_pdr.find(teid);
  if (pit == ul_s1u_teid2pfcp_pdr.end()) {
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs =
        std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>(
            new std::vector<std::shared_ptr<pfcp::pfcp_pdr>>());
    pdrs->push_back(pdr);
    std::pair<
        teid_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>
        entry(teid, pdrs);
    // Logger::pfcp_switch().info( "add_pfcp_ul_pdr_by_up_teid tunnel " TEID_FMT
    // " ", teid);
    ul_s1u_teid2pfcp_pdr.insert(entry);
  } else {
    // sort by precedence
    // const std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>&
    // spdrs = pit->second;
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>* pdrs = pit->second.get();
    for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it =
             pdrs->begin();
         it < pdrs->end(); ++it) {
      if (*(it->get()) < *(pdr.get())) {
        pit->second->insert(it, pdr);
        return;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_ul_pdrs_by_up_teid(const teid_t teid) {
  ul_s1u_teid2pfcp_pdr.erase(teid);
}

//------------------------------------------------------------------------------
void pfcp_switch::add_pfcp_dl_pdr_by_ue_ip(
    const uint32_t ue_ip, std::shared_ptr<pfcp::pfcp_pdr>& pdr) {
  folly::AtomicHashMap<
      uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>::
      const_iterator pit = ue_ipv4_hbo2pfcp_pdr.find(ue_ip);
  if (pit == ue_ipv4_hbo2pfcp_pdr.end()) {
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs =
        std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>(
            new std::vector<std::shared_ptr<pfcp::pfcp_pdr>>());
    pdrs->push_back(pdr);
    std::pair<
        uint32_t, std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>>
        entry(ue_ip, pdrs);
    ue_ipv4_hbo2pfcp_pdr.insert(entry);
    // Logger::pfcp_switch().info( "add_pfcp_dl_pdr_by_ue_ip UE IP %8x", ue_ip);
  } else {
    // sort by precedence
    // const std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>>&
    // spdrs = pit->second;
    std::vector<std::shared_ptr<pfcp::pfcp_pdr>>* pdrs = pit->second.get();
    for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it =
             pdrs->begin();
         it < pdrs->end(); ++it) {
      if (*(it->get()) < *(pdr.get())) {
        pit->second->insert(it, pdr);
        return;
      }
    }
  }
}
//------------------------------------------------------------------------------
void pfcp_switch::remove_pfcp_dl_pdrs_by_ue_ip(const uint32_t ue_ip) {
  ue_ipv4_hbo2pfcp_pdr.erase(ue_ip);
}
//------------------------------------------------------------------------------
std::string pfcp_switch::to_string() const {
  std::string s = {};
  for (const auto& it : up_seid2pfcp_sessions) {
    s.append(it.second->to_string());
  }
  return s;
}

//------------------------------------------------------------------------------
bool pfcp_switch::create_packet_in_access(
    std::shared_ptr<pfcp::pfcp_pdr>& pdr, const pfcp::fteid_t& in,
    uint8_t& cause) {
  cause = CAUSE_VALUE_REQUEST_ACCEPTED;
  add_pfcp_ul_pdr_by_up_teid(in.teid, pdr);
  return true;
}

//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_establishment_request(
    std::shared_ptr<itti_sxab_session_establishment_request> sreq,
    itti_sxab_session_establishment_response* resp) {
  itti_sxab_session_establishment_request* req = sreq.get();
  pfcp::fseid_t fseid                          = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};

  if (req->pfcp_ies.get(fseid)) {
    std::shared_ptr<pfcp::pfcp_session> s = {};
    bool exist            = get_pfcp_session_by_cp_fseid(fseid, s);
    pfcp_session* session = nullptr;
    if (not exist) {
      session = new pfcp_session(fseid, generate_seid());

      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          session->cleanup();
          delete session;
          break;
        }
      }

      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        //--------------------------------
        // Process PDR to be created
        cause.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        for (auto it : req->pfcp_ies.create_pdrs) {
          create_pdr& cr_pdr            = it;
          pfcp::fteid_t allocated_fteid = {};

          pfcp::far_id_t far_id = {};
          if (not cr_pdr.get(far_id)) {
            // should be caught in lower layer
            cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_FAR_ID;
            session->cleanup();
            delete session;
            break;
          }
          // create pdr after create far
          pfcp::create_far cr_far = {};
          if (not req->pfcp_ies.get(far_id, cr_far)) {
            // should be caught in lower layer
            cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
            session->cleanup();
            delete session;
            break;
          }

          if (not session->create(
                  cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
            session->cleanup();
            delete session;
            if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
              resp->pfcp_ies.set(offending_ie);
            }
            resp->pfcp_ies.set(cause);
            break;
          }
          pfcp::created_pdr created_pdr = {};
          created_pdr.set(cr_pdr.pdr_id.second);
          created_pdr.set(allocated_fteid);
          resp->pfcp_ies.set(created_pdr);
        }
      }

      if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
        s = std::shared_ptr<pfcp_session>(session);
        add_pfcp_session_by_cp_fseid(fseid, s);
        add_pfcp_session_by_up_seid(session->seid, s);
        // start_timer_min_commit_interval();
        // start_timer_max_commit_interval();

        pfcp::fseid_t up_fseid = {};
        spgwu_cfg.get_pfcp_fseid(up_fseid);
        up_fseid.seid = session->get_up_seid();
        resp->pfcp_ies.set(up_fseid);

        // Register session
        pfcp::node_id_t node_id = {};
        req->pfcp_ies.get(node_id);
        pfcp_associations::get_instance().notify_add_session(node_id, fseid);
      }
    } else {
      cause.cause_value = CAUSE_VALUE_REQUEST_REJECTED;
    }
  } else {
    // should be caught in lower layer
    cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
    offending_ie.offending_ie = PFCP_IE_F_SEID;
  }
  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING) ||
      (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)) {
    resp->pfcp_ies.set(offending_ie);
  }

#if DEBUG_IS_ON
  std::cout
      << "\n+------------------------------------------------------------------"
         "---------------------------------------------------------------------"
         "-----------------------------------------------------------+"
      << std::endl;
  std::cout
      << "| PFCP switch Packet Detection Rule list ordered by established "
         "sessions:                                                            "
         "                                                              |"
      << std::endl;
  std::cout
      << "+----------------+----+--------+--------+------------+---------------"
         "------------------------+----------------------+----------------+----"
         "---------------------------------------------------------+"
      << std::endl;
  std::cout
      << "|  SEID          |pdr |  far   |predence|   action   |        create "
         "outer hdr         tun id| rmv outer hdr  tun id|    UE IPv4     |    "
         "                                                         |"
      << std::endl;
  std::cout
      << "+----------------+----+--------+--------+------------+---------------"
         "------------------------+----------------------+----------------+----"
         "---------------------------------------------------------+"
      << std::endl;
  for (const auto& it : up_seid2pfcp_sessions) {
    std::cout << it.second->to_string() << std::endl;
  }
#endif
}
//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_modification_request(
    std::shared_ptr<itti_sxab_session_modification_request> sreq,
    itti_sxab_session_modification_response* resp) {
  itti_sxab_session_modification_request* req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid                   = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  failed_rule_id_t failed_rule      = {};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    pfcp::pfcp_session* session = s.get();

    pfcp::fseid_t fseid = {};
    if (req->pfcp_ies.get(fseid)) {
      Logger::pfcp_switch().warn(
          "TODO check carrefully update fseid in "
          "PFCP_SESSION_MODIFICATION_REQUEST");
      session->cp_fseid = fseid;
    }
    resp->seid = session->cp_fseid.seid;

    for (auto it : req->pfcp_ies.remove_pdrs) {
      remove_pdr& pdr = it;
      if (not session->remove(pdr, cause, offending_ie.offending_ie)) {
        if (cause.cause_value ==
            CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
          failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value = pdr.pdr_id.second.rule_id;
          resp->pfcp_ies.set(failed_rule);
          break;
        }
      }
    }
    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.remove_fars) {
        remove_far& far = it;
        if (not session->remove(far, cause, offending_ie.offending_ie)) {
          if (cause.cause_value ==
              CAUSE_VALUE_RULE_CREATION_MODIFICATION_FAILURE) {
            failed_rule.rule_id_type  = FAILED_RULE_ID_TYPE_FAR;
            failed_rule.rule_id_value = far.far_id.second.far_id;
            resp->pfcp_ies.set(failed_rule);
            break;
          }
        }
      }
    }

    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_fars) {
        create_far& cr_far = it;
        if (not session->create(cr_far, cause, offending_ie.offending_ie)) {
          break;
        }
      }
    }

    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.create_pdrs) {
        create_pdr& cr_pdr = it;

        pfcp::far_id_t far_id = {};
        if (not cr_pdr.get(far_id)) {
          // should be caught in lower layer
          cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_FAR_ID;
          break;
        }
        // create pdr after create far
        pfcp::create_far cr_far = {};
        if (not req->pfcp_ies.get(far_id, cr_far)) {
          // should be caught in lower layer
          cause.cause_value         = CAUSE_VALUE_MANDATORY_IE_MISSING;
          offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
          break;
        }

        pfcp::fteid_t allocated_fteid = {};
        if (not session->create(
                cr_pdr, cause, offending_ie.offending_ie, allocated_fteid)) {
          if (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING) {
            resp->pfcp_ies.set(offending_ie);
          }
          resp->pfcp_ies.set(cause);
          break;
        }
        pfcp::created_pdr created_pdr = {};
        created_pdr.set(cr_pdr.pdr_id.second);
        if (not allocated_fteid.is_zero()) {
          created_pdr.set(allocated_fteid);
        }
        resp->pfcp_ies.set(created_pdr);
      }
    }

    if (cause.cause_value == CAUSE_VALUE_REQUEST_ACCEPTED) {
      for (auto it : req->pfcp_ies.update_pdrs) {
        update_pdr& pdr     = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(pdr, cause_value)) {
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_PDR;
          failed_rule.rule_id_value    = pdr.pdr_id.rule_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
      for (auto it : req->pfcp_ies.update_fars) {
        update_far& far     = it;
        uint8_t cause_value = CAUSE_VALUE_REQUEST_ACCEPTED;
        if (not session->update(far, cause_value)) {
          cause.cause_value            = cause_value;
          failed_rule_id_t failed_rule = {};
          failed_rule.rule_id_type     = FAILED_RULE_ID_TYPE_FAR;
          failed_rule.rule_id_value    = far.far_id.far_id;
          resp->pfcp_ies.set(failed_rule);
        }
      }
    }
  }
  resp->pfcp_ies.set(cause);
  if ((cause.cause_value == CAUSE_VALUE_MANDATORY_IE_MISSING) ||
      (cause.cause_value == CAUSE_VALUE_CONDITIONAL_IE_MISSING)) {
    resp->pfcp_ies.set(offending_ie);
  }

#if DEBUG_IS_ON
  std::cout
      << "\n+------------------------------------------------------------------"
         "---------------------------------------------------------------------"
         "-----------------------------------------------------------+"
      << std::endl;
  std::cout
      << "| PFCP switch Packet Detection Rule list ordered by established "
         "sessions:                                                            "
         "                                                              |"
      << std::endl;
  std::cout
      << "+----------------+----+--------+--------+------------+---------------"
         "------------------------+----------------------+----------------+----"
         "---------------------------------------------------------+"
      << std::endl;
  std::cout
      << "|  SEID          |pdr |  far   |predence|   action   |        create "
         "outer hdr         tun id| rmv outer hdr  tun id|    UE IPv4     |    "
         "                                                         |"
      << std::endl;
  std::cout
      << "+----------------+----+--------+--------+------------+---------------"
         "------------------------+----------------------+----------------+----"
         "---------------------------------------------------------+"
      << std::endl;
  for (const auto& it : up_seid2pfcp_sessions) {
    std::cout << it.second->to_string() << std::endl;
  }
#endif
}
//------------------------------------------------------------------------------
void pfcp_switch::handle_pfcp_session_deletion_request(
    std::shared_ptr<itti_sxab_session_deletion_request> sreq,
    itti_sxab_session_deletion_response* resp) {
  itti_sxab_session_deletion_request* req = sreq.get();

  std::shared_ptr<pfcp::pfcp_session> s = {};
  pfcp::fseid_t fseid                   = {};
  pfcp::cause_t cause = {.cause_value = CAUSE_VALUE_REQUEST_ACCEPTED};
  pfcp::offending_ie_t offending_ie = {};
  failed_rule_id_t failed_rule      = {};

  if (not get_pfcp_session_by_up_seid(req->seid, s)) {
    cause.cause_value = CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
  } else {
    resp->seid = s->cp_fseid.seid;
    remove_pfcp_session(s);
  }
  pfcp_associations::get_instance().notify_del_session(fseid);
  resp->pfcp_ies.set(cause);

#if DEBUG_IS_ON
  std::cout
      << "\n+------------------------------------------------------------------"
         "---------------------------------------------------------------------"
         "-----------------------------------------------------------+"
      << std::endl;
  std::cout
      << "| PFCP switch Packet Detection Rule list ordered by established "
         "sessions:                                                            "
         "                                                              |"
      << std::endl;
  std::cout
      << "+----------------+----+--------+--------+------------+---------------"
         "------------------------+----------------------+----------------+----"
         "---------------------------------------------------------+"
      << std::endl;
  std::cout
      << "|  SEID          |pdr |  far   |predence|   action   |        create "
         "outer hdr         tun id| rmv outer hdr  tun id|    UE IPv4     |    "
         "                                                         |"
      << std::endl;
  std::cout
      << "+----------------+----+--------+--------+------------+---------------"
         "------------------------+----------------------+----------------+----"
         "---------------------------------------------------------+"
      << std::endl;
  for (const auto& it : up_seid2pfcp_sessions) {
    std::cout << it.second->to_string() << std::endl;
  }
#endif
}
//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(
    struct iphdr* const iph, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  if (!spgwu_cfg.nsf.bypass_ul_pfcp_rules) {
    std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs = {};
    if (get_pfcp_ul_pdrs_by_up_teid(tunnel_id, pdrs)) {
      bool nocp = false;
      bool buff = false;
      for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it_pdr =
               pdrs->begin();
           it_pdr < pdrs->end(); ++it_pdr) {
        if ((*it_pdr)->look_up_pack_in_access(
                iph, num_bytes, r_endpoint, tunnel_id)) {
          std::shared_ptr<pfcp::pfcp_session> ssession = {};
          uint64_t lseid                               = 0;
          if ((*it_pdr)->get(lseid)) {
            if (get_pfcp_session_by_up_seid(lseid, ssession)) {
              pfcp::far_id_t far_id = {};
              if ((*it_pdr)->get(far_id)) {
                std::shared_ptr<pfcp::pfcp_far> sfar = {};
                if (ssession->get(far_id.far_id, sfar)) {
                  // Maintain uplink QFI in session
                  uint8_t qfi   = (*it_pdr)->pdi.second.qfi.second.qfi;
                  ssession->qfi = qfi;
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff, 0);
                }
              }
            }
          }
          return;
        } else {
          Logger::pfcp_switch().info(
              "pfcp_session_look_up_pack_in_access failed PDR id %4x ",
              (*it_pdr)->pdr_id.rule_id);
        }
      }
    } else {
      // Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_access tunnel
      // " TEID_FMT " not found", tunnel_id);
      spgwu_s1u_inst->report_error_indication(r_endpoint, tunnel_id);
    }
  } else {
    // Do not check PFCP rules for all UL data packet
    if (no_internal_loop(iph, num_bytes)) {
      pfcp_switch_inst->send_to_core(
          reinterpret_cast<char* const>(iph), num_bytes);
    }
  }
}
//------------------------------------------------------------------------------
bool pfcp_switch::no_internal_loop(
    struct iphdr* const iph, const std::size_t num_bytes) {
  pdn_cfg_t& pdn = spgwu_cfg.pdns[0];
  if ((pdn.network_ipv4.s_addr == (iph->daddr & pdn.network_mask_ipv4_be)) &&
      ((be32toh(iph->daddr) & 0x000000FF) != 0X00000001)) {
    pfcp_session_look_up_pack_in_core((const char*) iph, num_bytes);
    return false;
  }
  return true;
}
//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_access(
    struct ipv6hdr* const ip6h, const std::size_t num_bytes,
    const endpoint& r_endpoint, const uint32_t tunnel_id) {
  // TODO
}
//------------------------------------------------------------------------------
void pfcp_switch::pfcp_session_look_up_pack_in_core(
    const char* buffer, const std::size_t num_bytes) {
  // Logger::pfcp_switch().info( "pfcp_session_look_up_pack_in_core %d bytes",
  // num_bytes);
  struct iphdr* iph = (struct iphdr*) buffer;
  std::shared_ptr<std::vector<std::shared_ptr<pfcp::pfcp_pdr>>> pdrs;
  if (iph->version == 4) {
    uint32_t ue_ip = be32toh(iph->daddr);
    if (get_pfcp_dl_pdrs_by_ue_ip(ue_ip, pdrs)) {
      bool nocp = false;
      bool buff = false;
      for (std::vector<std::shared_ptr<pfcp::pfcp_pdr>>::iterator it =
               pdrs->begin();
           it < pdrs->end(); ++it) {
        if ((*it)->look_up_pack_in_core(iph, num_bytes)) {
          std::shared_ptr<pfcp::pfcp_session> ssession = {};
          uint64_t lseid                               = 0;
          if ((*it)->get(lseid)) {
            if (get_pfcp_session_by_up_seid(lseid, ssession)) {
              pfcp::far_id_t far_id = {};
              if ((*it)->get(far_id)) {
                std::shared_ptr<pfcp::pfcp_far> sfar = {};
                uint8_t qfi                          = ssession->qfi;
                //#if TRACE_IS_ON
                //                Logger::pfcp_switch().trace(
                //                "pfcp_session_look_up_pack_in_core %d bytes,
                //                far id %08X", num_bytes, far_id);
                //#endif
                if (ssession->get(far_id.far_id, sfar)) {
                  //#if TRACE_IS_ON
                  //                  Logger::pfcp_switch().trace(
                  //                  "pfcp_session_look_up_pack_in_core %d
                  //                  bytes, got far, far id %08X", num_bytes,
                  //                  far_id);
                  //#endif
                  sfar->apply_forwarding_rules(iph, num_bytes, nocp, buff, qfi);
                  if (buff) {
                    //#if TRACE_IS_ON
                    //                    Logger::pfcp_switch().trace(
                    //                    "Buffering %d bytes, far id %08X",
                    //                    num_bytes, far_id);
                    //#endif
                    (*it)->buffering_requested(buffer, num_bytes);
                  }
                  if (nocp) {
                    //#if TRACE_IS_ON
                    //                    Logger::pfcp_switch().trace( "Notify
                    //                    CP %d bytes, far id %08X", num_bytes,
                    //                    far_id);
                    //#endif
                    (*it)->notify_cp_requested(ssession);
                  }
                }
              }
            }
          }
          return;
        } else {
          Logger::pfcp_switch().info(
              "look_up_pack_in_core failed PDR id %4x ", (*it)->pdr_id.rule_id);
        }
      }
    } else {
      Logger::pfcp_switch().info(
          "pfcp_session_look_up_pack_in_core UE IP %8x not found", ue_ip);
    }
  } else if (iph->version == 6) {
    // TODO;
  } else {
    Logger::pfcp_switch().info("Unknown IP version %d packet", iph->version);
  }
}
