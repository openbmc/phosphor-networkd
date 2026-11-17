#pragma once
#include "system_queries.hpp"

#include <array>
#include <cstdint>

namespace phosphor::network::system
{
/** @brief Clears out the interfaces and IPs configured for mocking */
void mock_clear();

/** @brief Adds an interface definition to the mock system */
void mock_addIF(const InterfaceInfo& info);

struct MockRouteInfo
{
    unsigned ifidx = 0; // interface index (RTA_OIF)
    uint8_t family = 0; // AF_INET or AF_INET6
    uint8_t dstLen = 0; // prefix length (0 = default route)
    // dst in network byte order; ignored when dstLen == 0
    std::array<uint8_t, 16> dst{};
};

/** @brief Queues a unicast route entry returned by the next RTM_GETROUTE
 *         dump. Must be called before the function under test. */
void mock_addRoute(const MockRouteInfo& route);
} // namespace phosphor::network::system
