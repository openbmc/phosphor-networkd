#pragma once
#include "system_queries.hpp"

namespace phosphor::network::system
{
/** @brief Clears out the interfaces and IPs configured for mocking */
void mock_clear();

/** @brief Adds an interface definition to the mock system */
void mock_addIF(const InterfaceInfo& info);
} // namespace phosphor::network::system
