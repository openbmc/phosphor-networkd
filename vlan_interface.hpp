#pragma once

#include "ethernet_interface.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Network/VLAN/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
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
class VlanInterface : public VlanIface,
                      public DeleteIface,
                      public EthernetInterface
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
         *  @param[in] objPath - Path to attach at.
         *  @param[in] dhcpEnabled - DHCP enable value.
         *  @param[in] vlanID - vlan identifier.
         *  @param[in] intf - ethernet interface object.
         *  @param[in] manager - network manager object.
         */
        VlanInterface(sdbusplus::bus::bus& bus,
                      const std::string& objPath,
                      bool dhcpEnabled,
                      uint32_t vlanID,
                      EthernetInterface& intf,
                      Manager& manager);

        /** @brief Delete this d-bus object.
         */
        void delete_() override;

        /** @brief writes the device configuration.
                   systemd reads this configuration file
                   and creates the vlan interface.*/
        void writeDeviceFile();

        /** @brief copy the mac address from the parent interface.*/
        void updateMacAddress()
        {
            MacAddressIntf::mACAddress(parentInterface.mACAddress());
        }

    private:

        /** @brief VLAN Identifier. */
        using VlanIface::id;

        EthernetInterface& parentInterface;

        friend class TestVlanInterface;
};

} // namespace network
} // namespace phosphor
