#pragma once

/** @brief Adds the given interface and addr info
 *         into the ifaddr list.
 *  @param[in] name - Interface name.
 *  @param[in] addr - IP address.
 *  @param[in] mask - subnet mask.
 *  @param[in] flags - Interface flags.
 */

void mock_addIP(const char* name, const char* addr, const char* mask,
                unsigned int flags);
