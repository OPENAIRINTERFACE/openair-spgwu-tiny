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

#include "fqdn.hpp"
#include "logger.hpp"
#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <thread>

#define MAX_NB_RESOLVE_TRIES 4
#define TIME_IN_SECS_BETWEEN_TRIES 2

bool fqdn::resolve(
    const std::string& host_name, std::string& address, uint32_t& port,
    uint8_t& addr_type, const std::string& protocol) {
  int tries = 0;
  Logger::upf_app().debug("Resolving a DNS (name %s)", host_name.c_str());
  while (tries < MAX_NB_RESOLVE_TRIES) {
    try {
      boost::asio::io_context io_context = {};
      Logger::upf_app().debug("Resolving DNS Try #%u", tries);

      boost::asio::ip::tcp::resolver resolver{io_context};
      boost::asio::ip::tcp::resolver::results_type endpoints =
          resolver.resolve(host_name, protocol);

      addr_type = 0;  // IPv4 by default
      for (auto it = endpoints.cbegin(); it != endpoints.cend(); it++) {
        // get the first Endpoint
        boost::asio::ip::tcp::endpoint endpoint = *it;
        address = endpoint.address().to_string();
        port    = endpoint.port();
        Logger::upf_app().debug(
            "Resolved a DNS (name %s, protocol %s): Ip Addr %s, port %u",
            host_name.c_str(), protocol.c_str(), address.c_str(), port);
        if (endpoint.address().is_v4())
          addr_type = 0;
        else
          addr_type = 1;
        return true;
      }
    } catch (std::exception& e) {
      tries++;
      if (tries == MAX_NB_RESOLVE_TRIES) {
        throw std::runtime_error(
            "Cannot resolve a DNS name " + std::string(e.what()) + " after " +
            std::to_string(tries) + " tries");
        return false;
      }
      std::this_thread::sleep_for(
          std::chrono::seconds(TIME_IN_SECS_BETWEEN_TRIES));
    }
  }

  return false;
}
