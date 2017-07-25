#pragma once

#include "types.hpp"
#include "util.hpp"

#include "xyz/openbmc_project/Object/Delete/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <string>

namespace phosphor
{
namespace network
{

class EthernetInterface;
class Manager;

using DeleteIface =
    sdbusplus::server::object::object<
        sdbusplus::xyz::openbmc_project::Object::server::Delete>;
        

/** @class VlanInterface
 *  @brief OpenBMC vlan Interface implementation.
 *  @details A concrete implementation for the vlan interface
 */
class VlanInterface : public DeleteIface, public EthernetInterface
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
         *  @param[in] interfaceName - Ethernet interface name.
         *  @param[in] vlanID - vlan identifier.
         *  @param[in] parent - parent object.
         */
        VlanInterface(sdbusplus::bus::bus& bus,
                      const std::string& objPath,
                      bool dhcpEnabled,
                      const uint8_t vlanID,
                      Manager& parent);

        /** @brief Delete this d-bus object.
         */
        void delete_() override;

        /** @brief no op for vlan interface. */
        bool dHCPEnabled(bool value)
        {
            return EthernetInterface::dHCPEnabled();
        }

    private:

        /** @brief writes the device configuration.
                   systemd reads this configuration file
                   and creates the vlan interface.*/

        void writeDeviceFile();

        /** @brief VLAN Identifier. */
        uint8_t vlanID;

        friend class TestVlanInterface;
};

} // namespace network
} // namespace phosphor
