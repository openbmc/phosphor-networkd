#pragma once

#include "config_parser.hpp"
#include "ethernet_interface.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/VLAN/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace network
{

class EthernetInterface;
class Manager;

using DeleteIface = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using VlanIface = sdbusplus::xyz::openbmc_project::Network::server::VLAN;

/** @class VlanInterface
 *  @brief OpenBMC vlan Interface implementation.
 *  @details A concrete implementation for the vlan interface
 */
class VlanInterface : public EthernetInterface,
                      public DeleteIface,
                      public VlanIface
{
  public:
    VlanInterface() = delete;
    VlanInterface(const VlanInterface&) = delete;
    VlanInterface& operator=(const VlanInterface&) = delete;
    VlanInterface(VlanInterface&&) = delete;
    VlanInterface& operator=(VlanInterface&&) = delete;
    virtual ~VlanInterface() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] manager - network manager object.
     *  @param[in] info - Interface information.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] config - The parsed configuation file.
     *  @param[in] vlanID - vlan identifier.
     *  @param[in] parent - ethernet interface object.
     *  @param[in] emitSignal - true if the object added signal needs to be
     *                          send.
     *  @param[in] enabled - Override the lookup of nicEnabled
     *
     *  This constructor is called during loading the VLAN Interface
     */
    VlanInterface(sdbusplus::bus_t& bus, Manager& manager,
                  const InterfaceInfo& info, std::string_view objRoot,
                  const config::Parser& config, uint16_t vlanID,
                  EthernetInterface& parent, bool emitSignal = true,
                  std::optional<bool> enabled = std::nullopt);

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    /** @brief sets the MAC address.
     *  @param[in] value - MAC address which needs to be set on the system.
     *  @returns macAddress of the interface or throws an error.
     */
    std::string macAddress(std::string value) override;

    /** @brief writes the device configuration.
               systemd reads this configuration file
               and creates the vlan interface.*/
    void writeDeviceFile();

  private:
    /** @brief VLAN Identifier. */
    using VlanIface::id;

    EthernetInterface& parentInterface;

    friend class TestVlanInterface;
};

} // namespace network
} // namespace phosphor
