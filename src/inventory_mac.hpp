#pragma once
#include <nlohmann/json_fwd.hpp>
#include <sdbusplus/bus.hpp>
#include <stdplus/pinned.hpp>

#include <memory>
#include <optional>
#include <string>

namespace phosphor::network
{

class Manager;

namespace inventory
{

struct MACConfig
{
    std::string inventory;
    std::string property = "MACAddress";
};

/** Parse a legacy inventory name or an object with Inventory and Property.
 *  Empty inventory names retain the legacy single-object fallback.
 */
std::optional<MACConfig> parseMACConfig(const nlohmann::json& value);

struct Runtime
{
    virtual ~Runtime() = default;
};
std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                               stdplus::PinnedRef<Manager> m);

} // namespace inventory
} // namespace phosphor::network
