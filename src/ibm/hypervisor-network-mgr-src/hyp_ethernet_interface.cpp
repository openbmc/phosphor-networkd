#include "hyp_ethernet_interface.hpp"

#include <phosphor-logging/lg2.hpp>

class HypEthInterface;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using BIOSConfigManager =
    sdbusplus::xyz::openbmc_project::BIOSConfig::server::Manager;

constexpr char biosEnumType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration";

constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

// The total number of vmi attributes in biosTableAttrs is 17
// 4 attributes of interface 0 - ipv4 address
// 4 attributes of interface 0 - ipv6 address
// 4 attributes of interface 1 - ipv4 address
// 4 attributes of interface 1 - ipv6 address
constexpr auto BIOS_ATTRS_SIZE = 17;

biosTableRetAttrValueType
    HypEthInterface::getAttrFromBiosTable(const std::string& attrName)
{
    try
    {
        using getAttrRetType =
            std::tuple<std::string, std::variant<std::string, int64_t>,
                       std::variant<std::string, int64_t>>;
        getAttrRetType ip;
        auto method = bus.get().new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                                BIOS_MGR_INTF, "GetAttribute");

        method.append(attrName);

        auto reply = bus.get().call(method);

        std::string type;
        std::variant<std::string, int64_t> currValue;
        std::variant<std::string, int64_t> defValue;
        reply.read(type, currValue, defValue);
        return currValue;
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        lg2::error(
            "Failed to get the attribute value from bios table. Error: {ERR}",
            "ERR", ex.what());
    }
    return "";
}

void HypEthInterface::watchBaseBiosTable()
{
    auto BIOSAttrUpdate = [this](sdbusplus::message::message& m) {
        std::map<std::string, std::variant<BiosBaseTableType>>
            interfacesProperties;

        std::string objName;
        m.read(objName, interfacesProperties);

        // Check if the property change signal is for BaseBIOSTable property
        // If found, proceed; else, continue to listen
        if (!interfacesProperties.contains("BaseBIOSTable"))
        {
            // Return & continue to listen
            return;
        }

        // Check if the IP address has changed (i.e., if current ip address in
        // the biosTableAttrs data member and ip address in bios table are
        // different)

        // the no. of interface supported is two
        constexpr auto MAX_INTF_SUPPORTED = 2;
        for (auto i = 0; i < MAX_INTF_SUPPORTED; i++)
        {
            std::string intf = "if" + std::to_string(i);

            for (std::string protocol : {"ipv4", "ipv6"})
            {
                std::string dhcpEnabled =
                    std::get<std::string>(getAttrFromBiosTable(
                        "vmi_" + intf + "_" + protocol + "_method"));

                // This method was intended to watch the bios table
                // property change signal and update the dbus object
                // whenever the dhcp server has provided an
                // IP from different range or changed its gateway/subnet mask
                // (or) when user updates the bios table ip attributes - patch
                // on /redfish/v1/Systems/system/Bios/Settings Because, in all
                // other cases, user configures ip properties that will be set
                // in the dbus object, followed by bios table updation. In this
                // dhcp case, the dbus will not be having the updated ip address
                // which is in bios table, also in the second case, where one
                // patches bios table attributes, the dbus object will not have
                // the updated values. This method is to sync the ip addresses
                // between the bios table & dbus object.

                // Get corresponding ethernet interface object
                std::string ethIntfLabel;
                if (intf == "if0")
                {
                    ethIntfLabel = "eth0";
                }
                else
                {
                    ethIntfLabel = "eth1";
                }

                // Get the list of all ethernet interfaces from the parent
                // data member to get the eth object corresponding to the
                // eth interface label above
                auto& ethIntfList = manager.get().getEthIntfList();
                auto findEthObj = ethIntfList.find(ethIntfLabel);

                if (findEthObj == ethIntfList.end())
                {
                    lg2::error("Cannot find ethernet object");
                    return;
                }

                const auto& ethObj = findEthObj->second;

                DHCPConf dhcpState = ethObj->dhcpEnabled();

                if ((dhcpState == HypEthInterface::DHCPConf::none) &&
                    ((dhcpEnabled == "IPv4DHCP") ||
                     (dhcpEnabled == "IPv6DHCP")))
                {
                    // There is a change in bios table method attribute (changed
                    // to dhcp) but dbus property contains static Change the
                    // corresponding dbus property to dhcp
                    lg2::info("Setting dhcp on the dbus object");
                    if (dhcpEnabled == "IPv4DHCP")
                    {
                        if (ethObj->dhcp4())
                        {
                            ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v4);
                            ethObj->dhcp4(true);
                        }
                    }
                    else if (dhcpEnabled == "IPv6DHCP")
                    {
                        if (ethObj->dhcp6())
                        {
                            ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v6);
                            ethObj->dhcp6(true);
                        }
                    }
                }
                else if ((dhcpState != HypEthInterface::DHCPConf::none) &&
                         ((dhcpEnabled == "IPv4Static") ||
                          (dhcpEnabled == "IPv6Static")))
                {
                    // There is a change in bios table method attribute (changed
                    // to static) but dbus property contains dhcp Change the
                    // corresponding dbus property to static

                    if (dhcpEnabled == "IPv4Static")
                    {
                        if (dhcpState == HypEthInterface::DHCPConf::v6)
                        {
                            // no change
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::both)
                        {
                            ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v6);
                            ethObj->dhcp4(false);
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::v4)
                        {
                            ethObj->dhcpEnabled(
                                HypEthInterface::DHCPConf::none);
                            ethObj->dhcp4(false);
                        }
                    }
                    else if (dhcpEnabled == "IPv6Static")
                    {
                        if (dhcpState == HypEthInterface::DHCPConf::v4)
                        {
                            // no change
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::both)
                        {
                            ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v4);
                            ethObj->dhcp6(false);
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::v6)
                        {
                            ethObj->dhcpEnabled(
                                HypEthInterface::DHCPConf::none);
                            ethObj->dhcp6(false);
                        }
                    }
                }

                const auto& ipAddrs = ethObj->addrs;

                std::string ipAddr;
                std::string currIpAddr;
                std::string gateway;
                uint8_t prefixLen = 0;

                auto biosTableAttrs = manager.get().getBIOSTableAttrs();
                for (const auto& attr : biosTableAttrs)
                {
                    // Get ip address
                    if ((attr.first)
                            .ends_with(intf + "_" + protocol + "_ipaddr"))
                    {
                        currIpAddr = std::get<std::string>(attr.second);
                        if (currIpAddr.empty())
                        {
                            lg2::info("Current IP in biosAttrs copy is empty");
                            return;
                        }
                        ipAddr = std::get<std::string>(
                            getAttrFromBiosTable(attr.first));
                        if (ipAddr != currIpAddr)
                        {
                            // Ip address has changed
                            for (auto& addrs : ipAddrs)
                            {
                                if (((protocol == "ipv4") &&
                                     ((addrs.first).find(".") !=
                                      std::string::npos)) ||
                                    ((protocol == "ipv6") &&
                                     ((addrs.first).find(":") !=
                                      std::string::npos)))
                                {
                                    auto& ipObj = addrs.second;
                                    ipObj->HypIP::address(ipAddr);
                                    setIpPropsInMap(attr.first, ipAddr,
                                                    "String");
                                    break;
                                }
                            }
                            return;
                        }
                    }

                    // Get gateway
                    if ((attr.first)
                            .ends_with(intf + "_" + protocol + "_gateway"))
                    {
                        std::string currGateway =
                            std::get<std::string>(attr.second);
                        if (currGateway.empty())
                        {
                            lg2::info(
                                "Current Gateway in biosAttrs copy is empty");
                            return;
                        }
                        gateway = std::get<std::string>(
                            getAttrFromBiosTable(attr.first));
                        if (gateway != currGateway)
                        {
                            // Gateway has changed
                            for (auto& addrs : ipAddrs)
                            {
                                if (((protocol == "ipv4") &&
                                     ((addrs.first).find(".") !=
                                      std::string::npos)) ||
                                    ((protocol == "ipv6") &&
                                     ((addrs.first).find(":") !=
                                      std::string::npos)))
                                {
                                    auto& ipObj = addrs.second;
                                    ipObj->HypIP::gateway(gateway);
                                    setIpPropsInMap(attr.first, gateway,
                                                    "String");
                                    // Set default gateway if it is v6 on the
                                    // respective eth interface
                                    if (ipObj->type() == HypIP::Protocol::IPv6)
                                    {
                                        // This method is registered from eth0
                                        // by default. Hence, "this" will point
                                        // to eth0. Parse through the ethernet
                                        // interfaces list and update the
                                        // gateway of the respectie ethernet
                                        // interface
                                        for (auto& ethIntf :
                                             manager.get().getEthIntfList())
                                        {
                                            std::string ipObjPath =
                                                ipObj->getObjectPath();
                                            if (ipObjPath.find(ethIntf.first) !=
                                                std::string::npos)
                                            {
                                                ethIntf.second
                                                    ->HypEthernetIntf::
                                                        defaultGateway6(
                                                            gateway);
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                            return;
                        }
                    }

                    // Get prefix length
                    if ((attr.first)
                            .ends_with(intf + "_" + protocol +
                                       "_prefix_length"))
                    {
                        uint8_t currPrefixLen = static_cast<uint8_t>(
                            std::get<int64_t>(attr.second));
                        prefixLen = static_cast<uint8_t>(std::get<int64_t>(
                            getAttrFromBiosTable(attr.first)));
                        if (prefixLen != currPrefixLen)
                        {
                            // Prefix length has changed"
                            for (auto& addrs : ipAddrs)
                            {
                                if (((protocol == "ipv4") &&
                                     ((addrs.first).find(".") !=
                                      std::string::npos)) ||
                                    ((protocol == "ipv6") &&
                                     ((addrs.first).find(":") !=
                                      std::string::npos)))
                                {
                                    auto& ipObj = addrs.second;
                                    ipObj->HypIP::prefixLength(prefixLen);
                                    setIpPropsInMap(attr.first, prefixLen,
                                                    "Integer");
                                    break;
                                }
                            }
                            return;
                        }
                    }
                }
            }
        }
        return;
    };

    phosphor::network::matchBIOSAttrUpdate = std::make_unique<
        sdbusplus::bus::match::match>(
        bus,
        "type='signal',member='PropertiesChanged',interface='org.freedesktop."
        "DBus.Properties',arg0namespace='xyz.openbmc_project.BIOSConfig."
        "Manager'",
        BIOSAttrUpdate);
}

void HypEthInterface::setIpPropsInMap(
    std::string attrName, std::variant<std::string, int64_t> attrValue,
    std::string attrType)
{
    manager.get().setBIOSTableAttr(attrName, attrValue, attrType);
}

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.get().getBIOSTableAttrs();
}

void HypEthInterface::updateIPAddress(std::string ip, std::string updatedIp)
{
    auto it = addrs.find(ip);
    if (it != addrs.end())
    {
        auto& ipObj = it->second;

        // Delete the ip address from the local copy (addrs)
        // and update it with the new ip and ip address object
        if (deleteObject(ip))
        {
            addrs.emplace(updatedIp, std::move(ipObj));
            lg2::info("Successfully updated ip address");
            return;
        }
        lg2::error("Updation of ip address not successful");
        return;
    }
}

bool HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        lg2::error("DeleteObject:Unable to find the object.");
        return false;
    }
    addrs.erase(it);
    lg2::info("Successfully deleted the ip address object");
    return true;
}

std::string HypEthInterface::getIntfLabel()
{
    // The bios table attributes will be named in the following format:
    // vmi_if0_ipv4/ipv6_<attrName>. Hence, this method returns if0/if1
    // based on the eth interface label eth0/eth1 in the object path
    const std::string ethIntfLabel =
        objectPath.str.substr(objectPath.str.rfind("/") + 1);
    if (ethIntfLabel == "eth0")
    {
        return "if0";
    }
    else if (ethIntfLabel == "eth1")
    {
        return "if1";
    }
    return "";
}

void HypEthInterface::createIPAddressObjects()
{
    // Access the biosTableAttrs of the parent object to create the ip address
    // object
    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        lg2::error("Wrong interface name");
        return;
    }
    std::string ipAddr;
    HypIP::AddressOrigin ipOrigin;
    uint8_t ipPrefixLength;
    std::string ipGateway;

    auto biosTableAttrs = manager.get().getBIOSTableAttrs();

    if (biosTableAttrs.size() < BIOS_ATTRS_SIZE)
    {
        lg2::info("Creating ip address object with default values");
        std::optional<stdplus::InAnyAddr> addrv4, addrv6;
        addrv4.emplace(stdplus::fromStr<stdplus::In4Addr>("0.0.0.0"));
        addrv6.emplace(stdplus::fromStr<stdplus::In6Addr>("::"));

        std::optional<stdplus::SubnetAny> ifaddrv4, ifaddrv6;
        ifaddrv4.emplace(*addrv4, 0);
        ifaddrv6.emplace(*addrv6, 128);
        if (intfLabel == "if0")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv4");
            addrs.emplace("eth0/v4",
                          std::make_unique<HypIPAddress>(
                              bus,
                              sdbusplus::message::object_path(objectPath.str +
                                                              "/ipv4/addr0"),
                              *this, *ifaddrv4, "0.0.0.0",
                              HypIP::AddressOrigin::Static, intfLabel));

            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv6");
            addrs.emplace("eth0/v6",
                          std::make_unique<HypIPAddress>(
                              bus,
                              sdbusplus::message::object_path(objectPath.str +
                                                              "/ipv6/addr0"),
                              *this, *ifaddrv6,
                              "::", HypIP::AddressOrigin::Static, intfLabel));
        }
        else if (intfLabel == "if1")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv4");
            addrs.emplace("eth1/v4",
                          std::make_unique<HypIPAddress>(
                              bus,
                              sdbusplus::message::object_path(objectPath.str +
                                                              "/ipv4/addr0"),
                              *this, *ifaddrv4, "0.0.0.0",
                              HypIP::AddressOrigin::Static, intfLabel));

            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel, "ipv6");
            addrs.emplace("eth1/v6",
                          std::make_unique<HypIPAddress>(
                              bus,
                              sdbusplus::message::object_path(objectPath.str +
                                                              "/ipv6/addr0"),
                              *this, *ifaddrv6,
                              "::", HypIP::AddressOrigin::Static, intfLabel));
        }
        return;
    }

    for (std::string protocol : {"ipv4", "ipv6"})
    {
        std::string vmi_prefix = "vmi_" + intfLabel + "_" + protocol + "_";

        auto biosTableItr = biosTableAttrs.find(vmi_prefix + "method");
        if (biosTableItr != biosTableAttrs.end())
        {
            std::string ipType = std::get<std::string>(biosTableItr->second);
            if (ipType.find("Static") != std::string::npos)
            {
                ipOrigin = HypIP::AddressOrigin::Static;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    dhcp4(false);
                }
                else if (protocol == "ipv6")
                {
                    dhcp6(false);
                }
            }
            else if (ipType.find("DHCP") != std::string::npos)
            {
                ipOrigin = HypIP::AddressOrigin::DHCP;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    dhcp4(true);
                }
                else if (protocol == "ipv6")
                {
                    dhcp6(true);
                }
            }
            else
            {
                lg2::error("Error - Neither Static/DHCP");
            }
        }
        else
        {
            continue;
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "ipaddr");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipAddr = std::get<std::string>(biosTableItr->second);
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "prefix_length");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipPrefixLength =
                static_cast<uint8_t>(std::get<int64_t>(biosTableItr->second));
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "gateway");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipGateway = std::get<std::string>(biosTableItr->second);
        }

        std::optional<stdplus::InAnyAddr> addr;
        try
        {
            if (protocol == "ipv4")
            {
                addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipAddr));
            }
            else if (protocol == "ipv6")
            {
                addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipAddr));
            }
            else
            {
                throw std::logic_error("Exhausted protocols");
            }
            if (!std::visit([](auto ip) { return validIntfIP(ip); }, *addr))
            {
                throw std::invalid_argument("not unicast");
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Invalid IP {NET_IP}: {ERROR}", "NET_IP", ipAddr,
                       "ERROR", e);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipAddr"),
                                  Argument::ARGUMENT_VALUE(ipAddr.c_str()));
        }
        std::optional<stdplus::SubnetAny> ifaddr;
        ifaddr.emplace(*addr, ipPrefixLength);
        std::string ipObjId = "addr0";

        addrs.emplace(ipAddr,
                      std::make_unique<HypIPAddress>(
                          bus,
                          sdbusplus::message::object_path(
                              objectPath.str + "/" + protocol + "/" + ipObjId),
                          *this, *ifaddr, ipGateway, ipOrigin, intfLabel));
    }
}

bool HypEthInterface::ipv6AcceptRA(bool value)
{
    auto currValue = ipv6AcceptRA();
    if (currValue != value)
    {
        HypEthernetIntf::ipv6AcceptRA(value);
    }
    return value;
}

std::string HypEthInterface::defaultGateway6(std::string gateway)
{
    try
    {
        if (!gateway.empty())
        {
            validateGateway<stdplus::In6Addr>(gateway);
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid IPv6 Gateway: {GATEWAY}, Error: {ERROR}", "GATEWAY",
                   gateway, "ERROR", e.what());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    if (HypEthernetIntf::defaultGateway6() == gateway)
    {
        return gateway;
    }
    // Set the corresponding ip address object's gateway
    for (auto& addr : addrs)
    {
        auto& ipObj = addr.second;
        if (ipObj->type() == HypIP::Protocol::IPv6)
        {
            if (ipObj->origin() == HypIP::AddressOrigin::Static)
            {
                HypEthernetIntf::defaultGateway6(gateway);
                // Update ipv6 gateway as well
                ipObj->gateway(gateway);
            }
            else
            {
                lg2::error(
                    "Cannot set IPv6 default gateway in DHCP mode to {GATEWAY}",
                    "GATEWAY", gateway);
                elog<InvalidArgument>(
                    Argument::ARGUMENT_NAME("GATEWAY"),
                    Argument::ARGUMENT_VALUE(gateway.c_str()));
            }
            break;
        }
    }
    return gateway;
}

bool HypEthInterface::dhcp4(bool value)
{
    auto currValue = dhcp4();
    if (currValue == value)
    {
        return value;
    }

    HypEthernetIntf::dhcp4(value);
    if (value)
    {
        if (dhcp6())
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::both);
        }
        else
        {
            // !v6DhcpEnabled
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v4);
        }
    }
    else
    {
        if (dhcp6())
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v6);
        }
        else
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::none);
        }
    }

    return value;
}

bool HypEthInterface::dhcp6(bool value)
{
    auto currValue = dhcp6();
    if (currValue == value)
    {
        return value;
    }

    HypEthernetIntf::dhcp6(value);
    if (value)
    {
        if (dhcp4())
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::both);
        }
        else
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v6);
        }
    }
    else
    {
        if (dhcp4())
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v4);
        }
        else
        {
            HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::none);
        }
    }
    return value;
}

ObjectPath HypEthInterface::ip(HypIP::Protocol protType, std::string ipaddress,
                               uint8_t prefixLength, std::string gateway)
{
    HypIP::AddressOrigin origin = HypIP::AddressOrigin::Static;

    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        lg2::info(
            "Static IP Config: Disabling DHCP on the interface: {INTERFACE}",
            "INTERFACE", interfaceName());
        switch (protType)
        {
            case HypIP::Protocol::IPv4:
                dhcp4(false);
                addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
                break;
            case HypIP::Protocol::IPv6:
                dhcp6(false);
                addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
        if (!std::visit([](auto ip) { return validIntfIP(ip); }, *addr))
        {
            throw std::invalid_argument("not unicast");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid IP {NET_IP}: {ERROR}", "NET_IP", ipaddress, "ERROR",
                   e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    std::optional<stdplus::SubnetAny> ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr.emplace(*addr, prefixLength);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX",
                   prefixLength, "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(prefixLength).c_str()));
    }

    try
    {
        if (!gateway.empty())
        {
            if (protType == HypIP::Protocol::IPv4)
            {
                validateGateway<stdplus::In4Addr>(gateway);
            }
            else if (protType == HypIP::Protocol::IPv6)
            {
                validateGateway<stdplus::In6Addr>(gateway);
            }
        }
        else
        {
            throw std::invalid_argument("Empty gateway");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid Gateway: {GATEWAY}, Error: {ERR}", "GATEWAY",
                   gateway, "ERR", e.what());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        lg2::error("Wrong interface name");
        return sdbusplus::message::details::string_path_wrapper();
    }

    const std::string ipObjId = "addr0";
    std::string protocol;
    std::string biosMethod;
    if (protType == HypIP::Protocol::IPv4)
    {
        protocol = "ipv4";
        biosMethod = "IPv4Static";
    }
    else if (protType == HypIP::Protocol::IPv6)
    {
        protocol = "ipv6";
        biosMethod = "IPv6Static";
    }

    std::string objPath = objectPath.str + "/" + protocol + "/" + ipObjId;

    for (auto& addr : addrs)
    {
        auto& ipObj = addr.second;
        std::string ipObjAddr = ipObj->address();
        uint8_t ipObjPrefixLen = ipObj->prefixLength();
        std::string ipObjGateway = ipObj->gateway();

        if ((ipaddress == ipObjAddr) && (prefixLength == ipObjPrefixLen) &&
            (gateway == ipObjGateway))
        {
            lg2::info("Trying to set same IP properties");
            return sdbusplus::message::object_path(objPath);
        }
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        break;
    }

    lg2::info(
        "Updating IP properties, ObjectPath: {OBJPATH}, Interface: {INTERFACE}, IP: {ADDRESS}, Gateway: {GATEWAY}, Prefix length: {PREFIXLENGTH}",
        "OBJPATH", objPath, "INTERFACE", intfLabel, "ADDRESS", ipaddress,
        "GATEWAY", gateway, "PREFIXLENGTH", prefixLength);

    addrs[ipaddress] = std::make_unique<HypIPAddress>(
        bus, sdbusplus::message::object_path(objPath), *this, *ifaddr, gateway,
        origin, intfLabel);

    PendingAttributesType pendingAttributes;
    auto& ipObj = addrs[ipaddress];

    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("origin"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::Enumeration),
                        biosMethod));

    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("address"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::String),
                        ipaddress));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("gateway"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::String),
                        gateway));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("prefixLength"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::Integer),
                        prefixLength));

    ipObj->updateBiosPendingAttrs(pendingAttributes);

    return sdbusplus::message::object_path(objPath);
}

HypEthInterface::DHCPConf HypEthInterface::dhcpEnabled(DHCPConf value)
{
    auto old4 = HypEthernetIntf::dhcp4();
    auto new4 = HypEthernetIntf::dhcp4(value == DHCPConf::v4 ||
                                       value == DHCPConf::both);
    auto old6 = HypEthernetIntf::dhcp6();
    auto new6 = HypEthernetIntf::dhcp6(value == DHCPConf::v6 ||
                                       value == DHCPConf::both);

    if (old4 == new4 && old6 == new6)
    {
        // if new value is the same as old value
        return value;
    }

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        bool v4Enabled = false;
        bool v6Enabled = false;
        HypEthernetIntf::DHCPConf newValue = HypEthernetIntf::DHCPConf::v4;

        if (value == HypEthernetIntf::DHCPConf::v4)
        {
            if ((old4 == false && old6 == false) || old4)
            {
                newValue = value;
                v4Enabled = true;
                v6Enabled = false;
            }
            else if ((old4 == true && old6 == true) || old6)
            {
                newValue = HypEthernetIntf::DHCPConf::both;
                v4Enabled = true;
                v6Enabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::v6)
        {
            if ((old4 == false && old6 == false) ||
                (old4 == true && old6 == true) || old6)
            {
                newValue = value;
                v4Enabled = false;
                v6Enabled = true;
            }
            else
            {
                newValue = HypEthernetIntf::DHCPConf::both;
                v4Enabled = true;
                v6Enabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::both)
        {
            newValue = HypEthernetIntf::DHCPConf::both;
            v4Enabled = true;
            v6Enabled = true;
        }

        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(newValue);

        PendingAttributesType pendingAttributes;
        ipAddrMapType::iterator itr = addrs.begin();
        while (itr != addrs.end())
        {
            std::string method;
            if ((itr->second)->type() == HypIP::Protocol::IPv4)
            {
                if (v4Enabled)
                {
                    method = "IPv4DHCP";
                    (itr->second)->origin(HypIP::AddressOrigin::DHCP);
                }
                else
                {
                    method = "IPv4Static";
                    // Reset IPv4 to the defaults only when dhcpv4 is disabled;
                    // if the old4 is false (which means static), then
                    // reset shouldn't happen in order to restore the static
                    // v4 configuration
                    if (old4 == true)
                    {
                        (itr->second)->resetBaseBiosTableAttrs("IPv4");
                    }
                }
            }
            else if ((itr->second)->type() == HypIP::Protocol::IPv6)
            {
                if (v6Enabled)
                {
                    method = "IPv6DHCP";
                    (itr->second)->origin(HypIP::AddressOrigin::DHCP);
                }
                else
                {
                    method = "IPv6Static";
                    // Reset IPv6 to the defaults only when dhcpv6 is disabled;
                    // if old6 is false (which means static), then
                    // reset shouldn't happen in order to restore the static
                    // v6 configuration
                    if (old6 == true)
                    {
                        (itr->second)->resetBaseBiosTableAttrs("IPv6");
                    }
                }
            }
            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    (itr->second)->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }

            if (std::next(itr) == addrs.end())
            {
                break;
            }
            itr++;
        }
        (itr->second)->updateBiosPendingAttrs(pendingAttributes);
    }
    else
    {
        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(HypEthernetIntf::DHCPConf::none);

        PendingAttributesType pendingAttributes;

        ipAddrMapType::iterator itr = addrs.begin();
        while (itr != addrs.end())
        {
            std::string method;
            if (((itr->second)->type() == HypIP::Protocol::IPv4) &&
                ((itr->second)->origin() == HypIP::AddressOrigin::DHCP))
            {
                method = "IPv4Static";
                (itr->second)->origin(HypIP::AddressOrigin::Static);
                (itr->second)->resetBaseBiosTableAttrs("IPv4");
            }
            else if (((itr->second)->type() == HypIP::Protocol::IPv6) &&
                     ((itr->second)->origin() == HypIP::AddressOrigin::DHCP))
            {
                method = "IPv6Static";
                (itr->second)->origin(HypIP::AddressOrigin::Static);
                (itr->second)->resetBaseBiosTableAttrs("IPv6");
            }

            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    (itr->second)->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }

            if (std::next(itr) == addrs.end())
            {
                break;
            }
            itr++;
        }
        (itr->second)->updateBiosPendingAttrs(pendingAttributes);
    }

    return value;
}

HypEthInterface::DHCPConf HypEthInterface::dhcpEnabled() const
{
    if (dhcp6())
    {
        return dhcp4() ? DHCPConf::both : DHCPConf::v6;
    }
    else if (dhcp4())
    {
        return DHCPConf::v4;
    }
    return DHCPConf::none;
}

} // namespace network
} // namespace phosphor
