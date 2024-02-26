#pragma once
#include "hyp_network_manager.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <xyz/openbmc_project/Network/SystemConfiguration/server.hpp>

#include <string>

namespace phosphor
{
namespace network
{

using SysConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::SystemConfiguration;

using Iface = sdbusplus::server::object_t<SysConfigIntf>;

class HypNetworkMgr; // forward declaration of network manager.

/** @class HypSysConfig
 *  @brief Network system configuration.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.HypSysConfig DBus API.
 */
class HypSysConfig : public Iface
{
  public:
    HypSysConfig() = delete;
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
    HypSysConfig(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                 const std::string& objPath, HypNetworkMgr& parent) :
        Iface(bus, objPath.c_str(), Iface::action::defer_emit),
        bus(bus), manager(parent){};

    /** @brief set the hostname of the system.
     *  @param[in] name - host name of the system.
     */
    std::string hostName(std::string name) override;

    /** @brief get hostname from bios and set the data member
     */
    void setHostName();

  protected:
    /** @brief get the hostname from the system by doing
     *         dbus call to hostnamed service.
     */
    std::string getHostNameFromBios() const;

    /** @brief set the hostname set in dbus obj in the basebiostable
     *  @param[in] name - hostname that is set in dbus obj
     */
    void setHostNameInBios(const std::string& name);

    /** @brief Persistent sdbusplus DBus bus connection. */
    stdplus::PinnedRef<sdbusplus::bus_t> bus;

    /** @brief Hyp Network Manager object. */
    HypNetworkMgr& manager;
};

} // namespace network
} // namespace phosphor
