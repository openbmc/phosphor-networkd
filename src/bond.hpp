#pragma once

#include "types.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message/native_types.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Network/Bond/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <string_view>

namespace phosphor
{
namespace network
{

using BondIntf = sdbusplus::xyz::openbmc_project::Network::server::Bond;

using BondObj = sdbusplus::server::object_t<
    BondIntf, sdbusplus::xyz::openbmc_project::Object::server::Delete>;

class EthernetInterface;

/** @class Bond
 *  @brief OpenBMC network bond implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.Bond dbus interface.
 */
class Bond : public BondObj
{
  public:
    using Mode = BondIntf::BondingMode;

    Bond() = delete;
    Bond(const Bond&) = delete;
    Bond& operator=(const Bond&) = delete;
    Bond(Bond&&) = delete;
    Bond& operator=(Bond&&) = delete;
    virtual ~Bond() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objRoot - Path to attach at.
     *  @param[in] eth - Parent object.
     *  @param[in] activeSlave - Active Slave.
     *  @param[in] miiMonitor - MII Monitor.
     *  @param[in] Mode - Bonding Mode.
     */

    Bond(sdbusplus::bus_t& bus, std::string_view objRoot,
         EthernetInterface& eth, std::string activeSlave, uint8_t miiMonitor,
         Mode mode);

    /** @brief Delete this d-bus object.
     */
    void delete_() override;

    using BondIntf::mode;
    Mode mode(Mode) override;
    using BondIntf::miiMonitor;
    uint8_t miiMonitor(uint8_t) override;
    using BondIntf::activeSlave;
    std::string activeSlave(std::string) override;

    void writeBondConfiguration(bool isActive);

    inline const auto& getObjPath() const
    {
        return objPath;
    }

    void updateMACAddress(std::string);

  private:
    /** @brief Parent Object. */
    EthernetInterface& eth;

    /** @brief Dbus object path */
    sdbusplus::message::object_path objPath;

    Bond(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
         EthernetInterface& eth, std::string activeSlave, uint8_t miiMonitor,
         Mode mode);
};

} // namespace network
} // namespace phosphor
