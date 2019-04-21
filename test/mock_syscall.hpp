#pragma once
#include <net/ethernet.h>

#include <optional>
#include <string>

/** @brief Clears out the interfaces and IPs configured for mocking
 */
void mock_clear();

/** @brief Adds an address string to index mapping and MAC mapping
 *
 *  @param[in] name - Interface name
 *  @param[in] idx  - Interface index
 *  @param[in] mac  - Interface MAC address
 */
void mock_addIF(const std::string& name, int idx,
                const std::optional<ether_addr>& mac = std::nullopt);
