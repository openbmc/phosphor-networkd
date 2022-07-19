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

constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

// The total number of vmi attributes defined in biosTableAttrs
// currently is 9:
// 4 attributes of interface 0
// 4 attributes of interface 1
// and 1 vmi_hostname attribute
constexpr auto BIOS_ATTRS_SIZE = 9;

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

            // Protocol list will be extended to ipv6 in future commit
            for (std::string protocol : {"ipv4"})
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
                    (dhcpEnabled == "IPv4DHCP"))
                {
                    // There is a change in bios table method attribute (changed
                    // to dhcp) but dbus property contains static Change the
                    // corresponding dbus property to dhcp
                    lg2::info("Setting dhcp on the dbus object");
                    if (ethObj->dhcp4())
                    {
                        ethObj->dhcpEnabled(HypEthInterface::DHCPConf::v4);
                        ethObj->dhcp4(true);
                    }
                }
                else if ((dhcpState != HypEthInterface::DHCPConf::none) &&
                         (dhcpEnabled == "IPv4Static"))
                {
                    // There is a change in bios table method attribute (changed
                    // to static) but dbus property contains dhcp Change the
                    // corresponding dbus property to static

                    if (dhcpEnabled == "IPv4Static")
                    {
                        if (dhcpState == HypEthInterface::DHCPConf::none)
                        {
                            // no change
                        }
                        else if (dhcpState == HypEthInterface::DHCPConf::v4)
                        {
                            ethObj->dhcpEnabled(
                                HypEthInterface::DHCPConf::none);
                            ethObj->dhcp4(false);
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
                                if ((protocol == "ipv4") &&
                                    ((addrs.first).find(".") !=
                                     std::string::npos))
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
                                if ((protocol == "ipv4") &&
                                    ((addrs.first).find(".") !=
                                     std::string::npos))
                                {
                                    auto& ipObj = addrs.second;
                                    ipObj->HypIP::gateway(gateway);
                                    setIpPropsInMap(attr.first, gateway,
                                                    "String");
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
                                if ((protocol == "ipv4") &&
                                    ((addrs.first).find(".") !=
                                     std::string::npos))
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
    // This method returns if0/if1 based on the eth
    // interface label eth0/eth1 in the object path
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
        std::optional<stdplus::InAnyAddr> addr;
        addr.emplace(stdplus::fromStr<stdplus::In4Addr>("0.0.0.0"));

        std::optional<stdplus::SubnetAny> ifaddr;
        ifaddr.emplace(*addr, 0);
        if (intfLabel == "if0")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth0", std::make_unique<HypIPAddress>(
                                      bus,
                                      sdbusplus::message::object_path(
                                          objectPath.str + "/ipv4/addr0"),
                                      *this, *ifaddr, "0.0.0.0",
                                      HypIP::AddressOrigin::Static, intfLabel));
        }
        else if (intfLabel == "if1")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth1", std::make_unique<HypIPAddress>(
                                      bus,
                                      sdbusplus::message::object_path(
                                          objectPath.str + "/ipv4/addr0"),
                                      *this, *ifaddr, "0.0.0.0",
                                      HypIP::AddressOrigin::Static, intfLabel));
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

bool HypEthInterface::dhcp4(bool value)
{
    auto currValue = dhcp4();
    if (currValue != value)
    {
        HypEthernetIntf::dhcp4(value);
    }
    return value;
}

bool HypEthInterface::dhcp6(bool value)
{
    auto currValue = dhcp6();
    if (currValue != value)
    {
        HypEthernetIntf::dhcp6(value);
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
                validateGateway<stdplus::In4Addr>(gateway);
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
    if (protType == HypIP::Protocol::IPv4)
    {
        protocol = "ipv4";
    }
    else if (protType == HypIP::Protocol::IPv6)
    {
        protocol = "ipv6";
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
                                       value == DHCPConf::v4v6stateless ||
                                       value == DHCPConf::both);
    auto old6 = HypEthernetIntf::dhcp6();
    auto new6 = HypEthernetIntf::dhcp6(value == DHCPConf::v6 ||
                                       value == DHCPConf::both);
    auto oldra = HypEthernetIntf::ipv6AcceptRA();
    auto newra = HypEthernetIntf::ipv6AcceptRA(
        value == DHCPConf::v6stateless || value == DHCPConf::v4v6stateless ||
        value == DHCPConf::v6 || value == DHCPConf::both);

    if (old4 == new4 || old6 == new6 || oldra == newra)
    {
        // if new value is the same as old value
        return value;
    }

    HypEthernetIntf::dhcpEnabled(value);

    std::unique_ptr<HypIPAddress> ipObj;
    std::string method;

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        for (auto& itr : addrs)
        {
            ipObj = std::move(itr.second);

            std::string method;
            if (ipObj->type() == HypIP::Protocol::IPv4)
            {
                method = "IPv4DHCP";
            }
            else if (ipObj->type() == HypIP::Protocol::IPv6)
            {
                method = "IPv6DHCP";
            }
            break;
        }
    }
    else
    {
        for (auto& itr : addrs)
        {
            ipObj = std::move(itr.second);

            std::string method;
            if (ipObj->type() == HypIP::Protocol::IPv4)
            {
                method = "IPv4Static";
            }
            else if (ipObj->type() == HypIP::Protocol::IPv6)
            {
                method = "IPv6Static";
            }
            break;
        }
    }

    PendingAttributesType pendingAttributes;
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("origin"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::Enumeration),
                        method));
    ipObj->updateBiosPendingAttrs(pendingAttributes);
    lg2::info("Updating the ip address properties");

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
        return ipv6AcceptRA() ? DHCPConf::v4v6stateless : DHCPConf::v4;
    }
    return ipv6AcceptRA() ? DHCPConf::v6stateless : DHCPConf::none;
}

} // namespace network
} // namespace phosphor
