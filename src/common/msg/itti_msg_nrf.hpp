/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
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

/*
 *  itti_msg_nrf.hpp
 *
 *  Created on:
 *  Author:
 */

#ifndef ITTI_MSG_NRF_HPP_INCLUDED_
#define ITTI_MSG_NRF_HPP_INCLUDED_

#include "itti_msg.hpp"
#include "spgwu_profile.hpp"
//#include "PatchItem.h"

class itti_nrf_msg : public itti_msg {
 public:
  itti_nrf_msg(const itti_msg_type_t msg_type, const task_id_t orig,
               const task_id_t dest)
      :
      itti_msg(msg_type, orig, dest) {

  }
  itti_nrf_msg(const itti_nrf_msg &i)
      :
      itti_msg(i) {
  }
  itti_nrf_msg(const itti_nrf_msg &i, const task_id_t orig,
               const task_id_t dest)
      :
      itti_nrf_msg(i) {
    origin = orig;
    destination = dest;
  }

};

//-----------------------------------------------------------------------------
class itti_nrf_register_nf_instance_request : public itti_nrf_msg {
 public:
  itti_nrf_register_nf_instance_request(const task_id_t orig,
                                        const task_id_t dest)
      : itti_nrf_msg(NRF_REGISTER_NF_INSTANCE_REQUEST, orig, dest),
        http_version(1) {}
  const char *get_msg_name() { return "NRF_REGISTER_NF_INSTANCE_REQUEST"; };

  spgwu::spgwu_profile profile;
  uint8_t http_version;
};

//-----------------------------------------------------------------------------
class itti_nrf_register_nf_instance_response : public itti_nrf_msg {
 public:
	itti_nrf_register_nf_instance_response(const task_id_t orig,
                                        const task_id_t dest)
      : itti_nrf_msg(NRF_REGISTER_NF_INSTANCE_RESPONSE, orig, dest),
        http_version(1) {}
  const char *get_msg_name() { return "NRF_REGISTER_NF_INSTANCE_RESPONSE"; };

  spgwu::spgwu_profile profile;
  uint8_t http_version;
  uint8_t http_response_code;
};


//-----------------------------------------------------------------------------
class itti_nrf_update_nf_instance_request : public itti_nrf_msg {
 public:
	itti_nrf_update_nf_instance_request(const task_id_t orig,
                                        const task_id_t dest)
      : itti_nrf_msg(NRF_UPDATE_NF_INSTANCE_REQUEST, orig, dest),
        http_version(1) {}
  const char *get_msg_name() { return "NRF_UPDATE_NF_INSTANCE_REQUEST"; };

  //std::vector<oai::smf_server::model::PatchItem> patch_items;
  uint8_t http_version;
  std::string upf_instance_id;
};

//-----------------------------------------------------------------------------
class itti_nrf_update_nf_instance_response : public itti_nrf_msg {
 public:
	itti_nrf_update_nf_instance_response(const task_id_t orig,
                                        const task_id_t dest)
      : itti_nrf_msg(NRF_UPDATE_NF_INSTANCE_RESPONSE, orig, dest),
        http_version(1) {}
  const char *get_msg_name() { return "NRF_UPDATE_NF_INSTANCE_RESPONSE"; };

  uint8_t http_version;
  std::string upf_instance_id;
  uint8_t http_response_code;
};


//-----------------------------------------------------------------------------
class itti_nrf_deregister_nf_instance : public itti_nrf_msg {
 public:
	itti_nrf_deregister_nf_instance(const task_id_t orig,
                                        const task_id_t dest)
      : itti_nrf_msg(NRF_DEREGISTER_NF_INSTANCE, orig, dest),
        http_version(1) {}
  const char *get_msg_name() { return "NRF_DEREGISTER_NF_INSTANCE"; };

  uint8_t http_version;
  std::string upf_instance_id;
};

#endif /* ITTI_MSG_NRF_HPP_INCLUDED_ */
