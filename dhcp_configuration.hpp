#pragma once

#include "config_parser.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <string>
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

using Iface = sdbusplus::server::object::object<ConfigIntf>;

/** @class Configuration
 *  @brief DHCP configuration.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Network.DHCP DBus interface.
 */
class Configuration : public Iface
{
  public:
    Configuration() = default;
    Configuration(const Configuration&) = delete;
    Configuration& operator=(const Configuration&) = delete;
    Configuration(Configuration&&) = delete;
    Configuration& operator=(Configuration&&) = delete;
    virtual ~Configuration() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Path to attach at.
     *  @param[in] parent - Parent object.
     */
    Configuration(sdbusplus::bus::bus& bus, const std::string& objPath,
                  Manager& parent) :
        Iface(bus, objPath.c_str(), true),
        bus(bus), manager(parent)
    {
        auto&& value = getDHCPPropFromConf("ClientIdentifier");
        std::string* clientId = std::get_if<std::string>(&value);
        if (clientId)
        {
            if (*clientId == "mac")
            {
                ConfigIntf::clientIdentifier(
                    DHCPConfiguration::ClientIdentifier::mac);
            }
            else if (*clientId == "duid")
            {
                ConfigIntf::clientIdentifier(
                    DHCPConfiguration::ClientIdentifier::duid);
            }
        }

        value = getDHCPPropFromConf("DUIDType");
        std::string* dUIDType = std::get_if<std::string>(&value);
        if (dUIDType)
        {
            if (*dUIDType == "vendor")
            {
                ConfigIntf::dUIDType(DHCPConfiguration::DUIDType::vendor);
            }
            else if (*dUIDType == "uid")
            {
                ConfigIntf::dUIDType(DHCPConfiguration::DUIDType::uid);
            }
            else if (*dUIDType == "link-layer-time")
            {
                ConfigIntf::dUIDType(
                    DHCPConfiguration::DUIDType::link_layer_time);
            }
            else if (*dUIDType == "link-layer")
            {
                ConfigIntf::dUIDType(DHCPConfiguration::DUIDType::link_layer);
            }
        }

        value = getDHCPPropFromConf("UseDNS");
        bool* dNSEnabled = std::get_if<bool>(&value);
        if (dNSEnabled)
        {
            ConfigIntf::dNSEnabled(*dNSEnabled);
        }

        value = getDHCPPropFromConf("UseNTP");
        bool* nTPEnabled = std::get_if<bool>(&value);
        if (nTPEnabled)
        {
            ConfigIntf::nTPEnabled(*nTPEnabled);
        }

        value = getDHCPPropFromConf("UseHostname");
        bool* hostNameEnabled = std::get_if<bool>(&value);
        if (hostNameEnabled)
        {
            ConfigIntf::hostNameEnabled(*hostNameEnabled);
        }

        value = getDHCPPropFromConf("SendHostname");
        bool* sendHostNameEnabled = std::get_if<bool>(&value);
        if (sendHostNameEnabled)
        {
            ConfigIntf::sendHostNameEnabled(*sendHostNameEnabled);
        }
        emit_object_added();
    }

    /** @brief This is used to generate client ID passed to
     *         the DHCP server.
     *
     *  @param[in] value - mac to generate client ID based on
     *                     MAC address.
     *                     duid to generate client ID based on
     *                     RFC-4361
     */
    ClientIdentifier clientIdentifier(ClientIdentifier value) override;

    /** @brief This specifies how the DUID should be generated.
     *
     *  @param[in] value - vendor - DUID based on machine-id
     *                     uid - DUID based on product UUID
     *                     link_layer_time - DUID based on MAC address
     *                     of the interface and an additional time value
     *                     link_layer - DUID based on MAC address
     */
    DUIDType dUIDType(DUIDType value) override;

    /** @brief If true then DNS servers received from the DHCP server
     *         will be used and take precedence over any statically
     *         configured ones.
     *  @param[in] value - true if DNS server needed from DHCP server
     *                     else false.
     */
    bool dNSEnabled(bool value) override;

    /** @brief If true then NTP servers received from the DHCP server
               will be used by systemd-timesyncd.
     *  @param[in] value - true if NTP server needed from DHCP server
     *                     else false.
     */
    bool nTPEnabled(bool value) override;

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

    /** @brief read the DHCP Prop value from the configuration file
     *  @param[in] prop - DHCP Prop name.
     */
    std::variant<bool, std::string>
        getDHCPPropFromConf(const std::string& prop);

    /* @brief Network Manager needed the below function to know the
     *        value of the properties (ntpEnabled,dnsEnabled,hostnameEnabled
              sendHostNameEnabled).
     *
     */
    using ConfigIntf::clientIdentifier;
    using ConfigIntf::dNSEnabled;
    using ConfigIntf::dUIDType;
    using ConfigIntf::hostNameEnabled;
    using ConfigIntf::nTPEnabled;
    using ConfigIntf::sendHostNameEnabled;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /** @brief Network Manager object. */
    phosphor::network::Manager& manager;
};

} // namespace dhcp
} // namespace network
} // namespace phosphor
