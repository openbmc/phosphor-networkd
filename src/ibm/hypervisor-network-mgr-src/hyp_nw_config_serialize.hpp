#pragma once

#include "config.h"

#include "types.hpp"

#include <filesystem>

namespace phosphor
{
namespace network
{
namespace persistdata
{
using NwConfigPropMap =
    std::map<std::string, std::variant<std::string, int64_t, bool>>;

const std::string HYP_NW_CONFIG_PERSIST_PATH = "/var/lib/network/hypervisor/";

/** @brief Serialize and persist list of n/w config properties.
 *  @param[in] list - list of hypervisor n/w config properties.
 *  @param[in] intf - hyp eth interface label (eth0/eth1).
 */
void serialize(const NwConfigPropMap& list, std::string intf);

/** @brief Deserialze a persisted list of n/w config properties.
 *  @param[out] list - list of n/w config properties.
 *  @return intf - hyp eth interface label (eth0/eth1).
 */
bool deserialize(NwConfigPropMap& list, std::string intf);

} // namespace persistdata
} // namespace network
} // namespace phosphor
