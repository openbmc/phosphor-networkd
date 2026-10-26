#pragma once
#include "system_queries.hpp"

#include <cstdint>
#include <string_view>

namespace phosphor::network::system
{
/** @brief Clears out the interfaces and IPs configured for mocking */
void mock_clear();

/** @brief Adds an interface definition to the mock system */
void mock_addIF(const InterfaceInfo& info);

void mock_setEthtoolSpeed(std::string_view ifname, uint16_t speed,
						 uint16_t speedHi);
} // namespace phosphor::network::system
