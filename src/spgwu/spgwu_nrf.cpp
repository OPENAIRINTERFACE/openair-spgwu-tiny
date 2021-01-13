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

/*! \file spgwu_nrf.cpp
 \brief
 \author  Lionel GAUTHIER, Tien-Thinh NGUYEN
 \company Eurecom
 \date 2021
 \email: lionel.gauthier@eurecom.fr, tien-thinh.nguyen@eurecom.fr
 */

#include "spgwu_nrf.hpp"

#include <stdexcept>

#include <curl/curl.h>
#include <pistache/http.h>
#include <pistache/mime.h>
#include <nlohmann/json.hpp>

#include "itti.hpp"
#include "logger.hpp"
#include "3gpp_29.510.h"
#include "spgwu_config.hpp"


using namespace Pistache::Http;
using namespace Pistache::Http::Mime;

using namespace spgwu;
using json = nlohmann::json;

extern itti_mw *itti_inst;
extern spgwu_nrf *spgwu_nrf_inst;
extern spgwu_config spgwu_cfg;
void spgwu_nrf_task(void *);

// To read content of the response from NF
static std::size_t callback(const char *in, std::size_t size, std::size_t num,
                            std::string *out) {
  const std::size_t totalBytes(size * num);
  out->append(in, totalBytes);
  return totalBytes;
}

//------------------------------------------------------------------------------
void spgwu_nrf_task(void *args_p) {
  const task_id_t task_id = TASK_SPGWU_NRF;
  itti_inst->notify_task_ready(task_id);

  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto *msg = shared_msg.get();
    switch (msg->msg_type) {

      case NRF_REGISTER_NF_INSTANCE_REQUEST:
        spgwu_nrf_inst->register_nf_instance(
            std::static_pointer_cast<itti_nrf_register_nf_instance_request>(
                shared_msg));
        break;

      case NRF_UPDATE_NF_INSTANCE_REQUEST:
        spgwu_nrf_inst->update_nf_instance(
            std::static_pointer_cast<itti_nrf_update_nf_instance_request>(
                shared_msg));
        break;

      case NRF_DEREGISTER_NF_INSTANCE:
        spgwu_nrf_inst->deregister_nf_instance(
            std::static_pointer_cast<itti_nrf_deregister_nf_instance>(
                shared_msg));
        break;

      case TERMINATE:
        if (itti_msg_terminate *terminate =
                dynamic_cast<itti_msg_terminate *>(msg)) {
          Logger::spgwu_app().info("Received terminate message");
          return;
        }
        break;

      default:
        Logger::spgwu_app().info("no handler for msg type %d", msg->msg_type);
    }

  } while (true);
}

//------------------------------------------------------------------------------
spgwu_nrf::spgwu_nrf() {
  Logger::spgwu_app().startup("Starting...");
  if (itti_inst->create_task(TASK_SPGWU_NRF, spgwu_nrf_task, nullptr)) {
    Logger::spgwu_app().error("Cannot create task TASK_SPGWU_NRF");
    throw std::runtime_error("Cannot create task TASK_SPGWU_NRF");
  }
  Logger::spgwu_app().startup("Started");
}

//-----------------------------------------------------------------------------------------------------
void spgwu_nrf::register_nf_instance(
    std::shared_ptr<itti_nrf_register_nf_instance_request> msg) {
  Logger::spgwu_app().debug(
      "Send NF Instance Registration to NRF (HTTP version %d)",
      msg->http_version);
  nlohmann::json json_data = {};
  msg->profile.to_json(json_data);

  std::string url;
  /*
      std::string(inet_ntoa(*((struct in_addr *)&smf_cfg.nrf_addr.ipv4_addr))) +
      ":" + std::to_string(smf_cfg.nrf_addr.port) + NNRF_NFM_BASE +
      smf_cfg.nrf_addr.api_version + NNRF_NF_REGISTER_URL +
      msg->profile.get_nf_instance_id();
*/

  Logger::spgwu_app().debug("Send NF Instance Registration to NRF (NRF URL %s)",
                          url.c_str());

  std::string body = json_data.dump();
  Logger::spgwu_app().debug(
      "Send NF Instance Registration to NRF, msg body: \n %s", body.c_str());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, NRF_CURL_TIMEOUT_MS);

    // Response information.
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    Logger::spgwu_app().debug("Response from NRF, Http Code: %d", httpCode);

    if (httpCode == 201) {
      json response_data = {};
      try {
        response_data = json::parse(*httpData.get());
      } catch (json::exception &e) {
        Logger::spgwu_app().warn("Could not parse json from the NRF response");
      }
      Logger::spgwu_app().debug("Response from NRF, Json data: \n %s",
                              response_data.dump().c_str());

      // send response to APP to process
      std::shared_ptr<itti_nrf_register_nf_instance_response> itti_msg =
          std::make_shared<itti_nrf_register_nf_instance_response>(
              TASK_SPGWU_NRF, TASK_SPGWU_APP);
      itti_msg->http_response_code = httpCode;
      itti_msg->http_version = msg->http_version;
      Logger::spgwu_app().debug("Registered SMF profile (from NRF)");
      itti_msg->profile.from_json(response_data);

      int ret = itti_inst->send_msg(itti_msg);
      if (RETURNok != ret) {
        Logger::spgwu_app().error(
            "Could not send ITTI message %s to task TASK_SPGWU_APP",
            itti_msg->get_msg_name());
      }
    } else {
      Logger::spgwu_app().warn("Could not get response from NRF");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
}

//-----------------------------------------------------------------------------------------------------
void spgwu_nrf::update_nf_instance(
    std::shared_ptr<itti_nrf_update_nf_instance_request> msg) {
  Logger::spgwu_app().debug("Send NF Update to NRF (HTTP version %d)",
                          msg->http_version);
/*
  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : msg->patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }
  std::string body = json_data.dump();
  Logger::spgwu_app().debug("Send NF Update to NRF (Msg body %s)", body.c_str());

  std::string url =
      std::string(inet_ntoa(*((struct in_addr *)&smf_cfg.nrf_addr.ipv4_addr))) +
      ":" + std::to_string(smf_cfg.nrf_addr.port) + NNRF_NFM_BASE +
      smf_cfg.nrf_addr.api_version + NNRF_NF_REGISTER_URL +
      msg->smf_instance_id;

  Logger::spgwu_app().debug("Send NF Update to NRF (NRF URL %s)", url.c_str());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, NRF_CURL_TIMEOUT_MS);

    if (msg->http_version == 2) {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
      // we use a self-signed test server, skip verification during debugging
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                       CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
    }

    // Response information.
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.length());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    Logger::spgwu_app().debug("Response from NRF, Http Code: %d", httpCode);

    if ((static_cast<http_response_codes_e>(httpCode) ==
         http_response_codes_e::HTTP_RESPONSE_CODE_OK) or
        (static_cast<http_response_codes_e>(httpCode) ==
         http_response_codes_e::HTTP_RESPONSE_CODE_NO_CONTENT)) {
      Logger::spgwu_app().debug("Got successful response from NRF");

      // TODO: in case of response containing NF profile
      // send response to APP to process
      std::shared_ptr<itti_nrf_update_nf_instance_response> itti_msg =
          std::make_shared<itti_nrf_update_nf_instance_response>(TASK_SPGWU_NRF,
                                                                 TASK_SPGWU_APP);
      itti_msg->http_response_code = httpCode;
      itti_msg->http_version = msg->http_version;
      itti_msg->smf_instance_id = msg->smf_instance_id;

      int ret = itti_inst->send_msg(itti_msg);
      if (RETURNok != ret) {
        Logger::spgwu_app().error(
            "Could not send ITTI message %s to task TASK_SPGWU_APP",
            itti_msg->get_msg_name());
      }
    } else {
      Logger::spgwu_app().warn("Could not get response from NRF");
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  */
}

//-----------------------------------------------------------------------------------------------------
void spgwu_nrf::deregister_nf_instance(
    std::shared_ptr<itti_nrf_deregister_nf_instance> msg) {
  Logger::spgwu_app().debug("Send NF De-register to NRF (HTTP version %d)",
                          msg->http_version);

  std::string url ;
  /*=
      std::string(inet_ntoa(*((struct in_addr *)&smf_cfg.nrf_addr.ipv4_addr))) +
      ":" + std::to_string(smf_cfg.nrf_addr.port) + NNRF_NFM_BASE +
      smf_cfg.nrf_addr.api_version + NNRF_NF_REGISTER_URL +
      msg->smf_instance_id;
*/
  Logger::spgwu_app().debug("Send NF De-register to NRF (NRF URL %s)",
                          url.c_str());

  curl_global_init(CURL_GLOBAL_ALL);
  CURL *curl = curl = curl_easy_init();

  if (curl) {
    CURLcode res = {};
    struct curl_slist *headers = nullptr;
    // headers = curl_slist_append(headers, "charsets: utf-8");
    headers = curl_slist_append(headers, "content-type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, NRF_CURL_TIMEOUT_MS);


    // Response information.
    long httpCode = {0};
    std::unique_ptr<std::string> httpData(new std::string());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, httpData.get());
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    Logger::spgwu_app().debug("Response from NRF, Http Code: %d", httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
}
