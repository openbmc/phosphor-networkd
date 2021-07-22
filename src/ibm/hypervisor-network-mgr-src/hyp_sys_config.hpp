#pragma once

#include "hyp_network_manager.hpp"
#include "system_configuration.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <xyz/openbmc_project/Network/SystemConfiguration/server.hpp>

namespace phosphor
{
namespace network
{

using SysConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

using Iface = sdbusplus::server::object::object<SysConfigIntf>;

class HypNetworkMgr; // forward declaration of network manager.

/** @class HypSysConfig
 *  @brief Network system configuration.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.HypSysConfig DBus API.
 */
class HypSysConfig : public Iface
{
  public:
    HypSysConfig() = default;
    HypSysConfig(const HypSysConfig&) = delete;
    HypSysConfig& operator=(const HypSysConfig&) = delete;
    HypSysConfig(HypSysConfig&&) = delete;
    HypSysConfig& operator=(HypSysConfig&&) = delete;
    virtual ~HypSysConfig() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent object.
     */
    HypSysConfig(sdbusplus::bus::bus& bus, const std::string& objPath,
                 HypNetworkMgr& parent);

    /** @brief set the hostname of the system.
     *  @param[in] name - host name of the system.
     */
    std::string hostName(std::string name) override;

  private:
    /** @brief get the hostname from the system by doing
     *         dbus call to hostnamed service.
     */
    std::string getHostNameFromBios() const;

    /** @brief set the hostname set in dbus obj in the basebiostable
     *  @param[in] name - hostname that is set in dbus obj
     */
    void setHostNameInBios(std::string name);

    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Hyp Network Manager object. */
    HypNetworkMgr& manager;
};

} // namespace network
} // namespace phosphor
