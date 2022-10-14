#pragma once
#include <net/ethernet.h>

#include <optional>
#include <string>

/** @brief Clears out the interfaces and IPs configured for mocking
 */
void mock_clear();

/** @brief Adds the given interface and addr info
 *         into the ifaddr list.
 *  @param[in] name - Interface name.
 *  @param[in] addr - IP address.
 *  @param[in] mask - subnet mask.
 *  @param[in] flags - Interface flags.
 */

void mock_addIP(const char* name, const char* addr, const char* mask);

/** @brief Adds an address string to index mapping and MAC mapping
 *
 *  @param[in] name - Interface name
 *  @param[in] idx  - Interface index
 *  @param[in] mac  - Interface MAC address
 */
void mock_addIF(const std::string& name, unsigned idx, unsigned flags = 0,
                std::optional<ether_addr> mac = std::nullopt,
                std::optional<unsigned> mtu = std::nullopt);
