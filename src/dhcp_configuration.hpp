#pragma once
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/zstring.hpp>
#include <xyz/openbmc_project/Network/DHCPConfiguration/server.hpp>

namespace phosphor
{
namespace network
{

class Manager; // forward declaration of network manager.

namespace dhcp
{

using ConfigIntf =
    sdbusplus::xyz::openbmc_project::Network::server::DHCPConfiguration;

using Iface = sdbusplus::server::object_t<ConfigIntf>;

/** @class Configuration
 *  @brief DHCP configuration.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.DHCP DBus interface.
 */
class Configuration : public Iface
{
  public:
    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent object.
     */
    Configuration(sdbusplus::bus_t& bus, stdplus::const_zstring objPath,
                  stdplus::PinnedRef<Manager> parent);

    /** @brief If true then DNS servers received from the DHCP server
     *         will be used and take precedence over any statically
     *         configured ones.
     *  @param[in] value - true if DNS server needed from DHCP server
     *                     else false.
     */
    bool dnsEnabled(bool value) override;

    /** @brief If true then NTP servers received from the DHCP server
               will be used by systemd-timesyncd.
     *  @param[in] value - true if NTP server needed from DHCP server
     *                     else false.
     */
    bool ntpEnabled(bool value) override;

    /** @brief If true then Hostname received from the DHCP server will
     *         be set as the hostname of the system
     *  @param[in] value - true if hostname needed from the DHCP server
     *                     else false.
     *
     */
    bool hostNameEnabled(bool value) override;

    /** @brief if true then it will cause an Option 12 field, i.e machine's
     *         hostname, will be included in the DHCP packet.
     *  @param[in] value - true if machine's host name needs to be included
     *         in the DHCP packet.
     */
    bool sendHostNameEnabled(bool value) override;

    /** @brief If true then DNS servers received from the DHCPv6 server
     *         will be used and take precedence over any statically
     *         configured ones.
     *  @param[in] value - true if DNS server needed from DHCPv6 server
     *                     else false.
     */
    bool dnsv6Enabled(bool value) override;

    /** @brief If true then NTP servers received from the DHCPv6 server
               will be used by systemd-timesyncd.
     *  @param[in] value - true if NTP server needed from DHCPv6 server
     *                     else false.
     */
    bool ntpv6Enabled(bool value) override;

    /** @brief If true then Hostname received from the DHCPv6 server will
     *         be set as the hostname of the system
     *  @param[in] value - true if hostname needed from the DHCPv6 server
     *                     else false.
     *
     */
    bool hostNamev6Enabled(bool value) override;

    /* @brief Network Manager needed the below function to know the
     *        value of the properties (ntpEnabled,dnsEnabled,hostnameEnabled
              sendHostNameEnabled).
     *
     */
    using ConfigIntf::dnsEnabled;
    using ConfigIntf::dnsv6Enabled;
    using ConfigIntf::hostNameEnabled;
    using ConfigIntf::hostNamev6Enabled;
    using ConfigIntf::ntpEnabled;
    using ConfigIntf::ntpv6Enabled;
    using ConfigIntf::sendHostNameEnabled;

  private:
    /** @brief Network Manager object. */
    stdplus::PinnedRef<Manager> manager;
};

} // namespace dhcp
} // namespace network
} // namespace phosphor
