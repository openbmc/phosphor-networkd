#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/zstring.hpp>
#include <string>
#include <xyz/openbmc_project/Network/SystemConfiguration/server.hpp>

namespace phosphor
{
namespace network
{

using SystemConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

using Iface = sdbusplus::server::object_t<SystemConfigIntf>;

class Manager; // forward declaration of network manager.

/** @class SystemConfiguration
 *  @brief Network system configuration.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.SystemConfiguration DBus API.
 */
class SystemConfiguration : public Iface
{
  public:
    SystemConfiguration() = default;
    SystemConfiguration(const SystemConfiguration&) = delete;
    SystemConfiguration& operator=(const SystemConfiguration&) = delete;
    SystemConfiguration(SystemConfiguration&&) = delete;
    SystemConfiguration& operator=(SystemConfiguration&&) = delete;
    virtual ~SystemConfiguration() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent object.
     */
    SystemConfiguration(sdbusplus::bus_t& bus, stdplus::const_zstring objPath);

    /** @brief set the hostname of the system.
     *  @param[in] name - host name of the system.
     */
    std::string hostName(std::string name) override;

  private:
    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief Monitor for hostname changes */
    sdbusplus::bus::match_t hostnamePropMatch;
};

} // namespace network
} // namespace phosphor
