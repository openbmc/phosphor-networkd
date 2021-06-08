#include "hyp_ethernet_interface.hpp"

class HypEthInterface;
class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

constexpr char IP_INTERFACE[] = "xyz.openbmc_project.Network.IP";

constexpr char biosStrType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.String";
constexpr char biosIntType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Integer";
constexpr char biosEnumType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration";

biosTableRetAttrValueType
    HypEthInterface::getAttrFromBiosTable(const std::string& attrName)
{
    constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
    constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
    constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

    try
    {
        using getAttrRetType =
            std::tuple<std::string, std::variant<std::string, int64_t>,
                       std::variant<std::string, int64_t>>;
        getAttrRetType ip;
        auto method = bus.new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                          BIOS_MGR_INTF, "GetAttribute");

        method.append(attrName);

        auto reply = bus.call(method);

        std::string type;
        std::variant<std::string, int64_t> currValue;
        std::variant<std::string, int64_t> defValue;
        reply.read(type, currValue, defValue);
        return currValue;
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        log<level::ERR>("Failed to get the attribute value from bios table",
                        entry("ERR=%s", ex.what()));
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
        log<level::INFO>("BaseBIOSTable - property changed");

        // Check if the IP address has changed (i.e., if current ip address in
        // the biosTableAttrs data member and ip address in bios table are
        // different)

        // the no. of interface supported is two
        constexpr auto MAX_INTF_SUPPORTED = 2;
        for (auto i = 0; i < MAX_INTF_SUPPORTED; i++)
        {
            std::string intf = "if" + std::to_string(i);

            bool isChanged = false;
            std::string dhcpEnabled = std::get<std::string>(
                getAttrFromBiosTable("vmi_" + intf + "_ipv4_method"));

            // Check if it is dhcp.
            // This method was intended to watch the bios table
            // property change signal and update the dbus object
            // whenever the dhcp server has provided an
            // IP from different range or changed its gateway/subnet mask.
            // Because, in all other cases,
            // user configures ip properties that will be set in the dbus
            // object, followed by bios table updation. Only in this dhcp case,
            // the dbus will not be having the updated ip address which
            // is in bios table. This method is to sync the ip addresses
            // between the bios table & dbus object.
            if (dhcpEnabled == "IPv4DHCP")
            {
                std::string ipAddr;
                std::string currIpAddr;
                std::string gateway;
                uint8_t prefixLen = 0;

                auto biosTableAttrs = manager.getBIOSTableAttrs();
                for (const auto& i : biosTableAttrs)
                {
                    // Get ip address
                    if ((i.first).ends_with("ipaddr"))
                    {
                        currIpAddr = std::get<std::string>(i.second);
                        if (currIpAddr.empty())
                        {
                            log<level::INFO>(
                                "Current IP in biosAttrs copy is empty");
                            return;
                        }
                        ipAddr = std::get<std::string>(
                            getAttrFromBiosTable(i.first));
                        if (ipAddr != currIpAddr)
                        {
                            log<level::INFO>("Ip address has changed");
                            isChanged = true;
                        }
                    }

                    // Get gateway
                    if ((i.first).ends_with("gateway"))
                    {
                        std::string currGateway =
                            std::get<std::string>(i.second);
                        if (currGateway.empty())
                        {
                            log<level::INFO>(
                                "Current Gateway in biosAttrs copy is empty");
                            return;
                        }
                        gateway = std::get<std::string>(
                            getAttrFromBiosTable(i.first));
                        if (gateway != currGateway)
                        {
                            log<level::INFO>("Gateway has changed");
                            isChanged = true;
                        }
                    }

                    // Get prefix length
                    if ((i.first).ends_with("prefix_length"))
                    {
                        uint8_t currPrefixLen =
                            static_cast<uint8_t>(std::get<int64_t>(i.second));
                        prefixLen = static_cast<uint8_t>(
                            std::get<int64_t>(getAttrFromBiosTable(i.first)));
                        if (prefixLen != currPrefixLen)
                        {
                            log<level::INFO>("Prefix length has changed");
                            isChanged = true;
                        }
                    }
                }

                if (isChanged)
                {
                    for (auto addr : addrs)
                    {
                        // dhcp server changes any/all of its properties
                        auto ipObj = addr.second;
                        ipObj->address(ipAddr);
                        if (prefixLen == 0)
                        {
                            // The setter method in the ip class, doesnot
                            // allow the user to set 0 as the prefix length.
                            // Since, this setting of 0 is within the
                            // implementation, setting the prefix length
                            // directly here.
                            ipObj->HypIP::prefixLength(prefixLen);

                            // Update the biosTableAttrs map with prefix
                            // length because we are not calling the setter
                            // method here.
                            std::string attrName =
                                ipObj->getHypPrefix() + "_prefix_length";
                            setIpPropsInMap(attrName, prefixLen, "Integer");
                        }
                        else
                        {
                            ipObj->prefixLength(prefixLen);
                        }
                        ipObj->gateway(gateway);
                        break;
                    }
                }
            }
            else
            {
                continue;
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

void HypEthInterface::dhcpCallbackMethod()
{
    auto biosTableAttrs = manager.getBIOSTableAttrs();
    std::shared_ptr<phosphor::network::HypIPAddress> ipAddrObj = NULL;

    for (const auto& ipAddr : addrs)
    {
        ipAddrObj = ipAddr.second;

        if (ipAddrObj == nullptr)
        {
            log<level::ERR>("Problem in retrieving the ip address object");
            return;
        }
        std::string address;
        std::string gateway;
        uint8_t prefixLenUint = 0;

        std::string hypPrefix = ipAddrObj->getHypPrefix();
        if (hypPrefix.empty())
        {
            log<level::ERR>(
                "Problem in retrieving the bios table attribute prefix");
            return;
        }
        for (const auto& biosAttr : biosTableAttrs)
        {
            if (biosAttr.first == hypPrefix + "ipaddr")
            {
                address = std::get<std::string>(biosAttr.second);
            }
            if (biosAttr.first == hypPrefix + "gateway")
            {
                gateway = std::get<std::string>(biosAttr.second);
            }
            if (biosAttr.first == hypPrefix + "prefix_length")
            {
                prefixLenUint =
                    static_cast<uint8_t>(std::get<int64_t>(biosAttr.second));
            }
        }
        ipAddrObj->address(address);
        ipAddrObj->gateway(gateway);
        ipAddrObj->prefixLength(prefixLenUint);
        break;
    }
}

std::shared_ptr<phosphor::network::HypIPAddress>
    HypEthInterface::getIPAddrObject(std::string attrName,
                                     std::string oldIpAddr = "")
{
    auto biosTableAttrs = manager.getBIOSTableAttrs();
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr == biosTableAttrs.end())
    {
        log<level::ERR>("Attribute not found in the list");
        return NULL;
    }

    std::map<std::string, std::shared_ptr<HypIPAddress>>::iterator findIp;
    if (oldIpAddr != "")
    {
        findIp = addrs.find(oldIpAddr);
    }
    else
    {
        findIp = addrs.find(std::get<std::string>(findAttr->second));
    }
    if (findIp == addrs.end())
    {
        log<level::ERR>("No corresponding ip address object found!");
        return NULL;
    }
    return findIp->second;
}

void HypEthInterface::setIpPropsInMap(
    std::string attrName, std::variant<std::string, int64_t> attrValue,
    std::string attrType)
{
    manager.setBIOSTableAttr(attrName, attrValue, attrType);
}

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.getBIOSTableAttrs();
}

void HypEthInterface::setBiosPropInDbus(
    std::shared_ptr<phosphor::network::HypIPAddress> ipObj,
    std::string attrName, std::variant<std::string, uint8_t> attrValue)
{
    std::string ipObjectPath = ipObj->getObjPath();

    if (attrName == "PrefixLength")
    {
        ipObj->prefixLength(std::get<uint8_t>(attrValue));
    }
    else if (attrName == "Gateway")
    {
        ipObj->gateway(std::get<std::string>(attrValue));
    }
    else if (attrName == "Address")
    {
        ipObj->address(std::get<std::string>(attrValue));
    }
    else if (attrName == "Origin")
    {
        std::string method = std::get<std::string>(attrValue);
        if (method == "IPv4Static")
        {
            ipObj->origin(HypIP::AddressOrigin::Static);
        }
        if (method == "IPv4DHCP")
        {
            ipObj->origin(HypIP::AddressOrigin::DHCP);
        }
    }
}

void HypEthInterface::updateIPAddress(std::string ip, std::string updatedIp)
{
    auto it = addrs.find(ip);
    if (it != addrs.end())
    {
        auto ipObj = it->second;
        if (deleteObject(ip))
        {
            addrs.emplace(updatedIp, ipObj);
            log<level::INFO>("Successfully updated ip address");
            return;
        }
        log<level::ERR>("Updation of ip address not successful");
        return;
    }
}

bool HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        log<level::ERR>("DeleteObject:Unable to find the object.");
        return false;
    }
    addrs.erase(it);
    log<level::INFO>("Successfully deleted the ip address object");
    return true;
}

std::string HypEthInterface::getIntfLabel()
{
    // The bios table attributes will be named in the following format:
    // vmi_if0_ipv4_<attrName>. Hence, this method returns if0/if1
    // based on the eth interface label eth0/eth1 in the object path
    const std::string ethIntfLabel =
        objectPath.substr(objectPath.rfind("/") + 1);
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
        log<level::ERR>("Wrong interface name");
        return;
    }
    std::string ipAddr;
    HypIP::Protocol ipProtocol;
    HypIP::AddressOrigin ipOrigin;
    uint8_t ipPrefixLength;
    std::string ipGateway;

    auto biosTableAttrs = manager.getBIOSTableAttrs();

    for (std::string protocol : {"ipv4", "ipv6"})
    {
        std::string vmi_prefix = "vmi_" + intfLabel + "_" + protocol + "_";

        auto biosTableItr = biosTableAttrs.find(vmi_prefix + "method");
        if (biosTableItr != biosTableAttrs.end())
        {
            std::string ipType = std::get<std::string>(biosTableItr->second);
            if (ipType.find("Static") != std::string::npos)
            {
                ipOrigin = IP::AddressOrigin::Static;
                // update the dhcp enabled property of the eth interface
                HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::none);
            }
            else if (ipType.find("DHCP") != std::string::npos)
            {
                ipOrigin = IP::AddressOrigin::DHCP;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v4);
                }
                else if (protocol == "ipv6")
                {
                    HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v6);
                }
            }
            else
            {
                log<level::ERR>("Error - Neither Static/DHCP");
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

        std::string ipObjId = "addr0";
        if (protocol == "ipv4")
        {
            ipProtocol = IP::Protocol::IPv4;
        }
        else if (protocol == "ipv6")
        {
            ipProtocol = IP::Protocol::IPv6;
        }

        addrs.emplace(ipAddr,
                      std::make_shared<phosphor::network::HypIPAddress>(
                          bus,
                          (objectPath + "/" + protocol + "/" + ipObjId).c_str(),
                          *this, ipProtocol, ipAddr, ipOrigin, ipPrefixLength,
                          ipGateway, intfLabel));
    }
}

void HypEthInterface::disableDHCP(HypIP::Protocol protocol)
{
    DHCPConf dhcpState = HypEthernetIntf::dhcpEnabled();
    if (dhcpState == HypEthInterface::DHCPConf::both)
    {
        if (protocol == HypIP::Protocol::IPv4)
        {
            dhcpEnabled(HypEthInterface::DHCPConf::v6);
        }
        else if (protocol == HypIP::Protocol::IPv6)
        {
            dhcpEnabled(HypEthInterface::DHCPConf::v4);
        }
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v4) &&
             (protocol == HypIP::Protocol::IPv4))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::none);
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v6) &&
             (protocol == HypIP::Protocol::IPv6))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::none);
    }
}

bool HypEthInterface::isDHCPEnabled(HypIP::Protocol family, bool ignoreProtocol)
{
    return (
        (HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::both) ||
        ((HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::v6) &&
         ((family == HypIP::Protocol::IPv6) || ignoreProtocol)) ||
        ((HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::v4) &&
         ((family == HypIP::Protocol::IPv4) || ignoreProtocol)));
}

ObjectPath HypEthInterface::ip(HypIP::Protocol protType, std::string ipaddress,
                               uint8_t prefixLength, std::string gateway)
{
    if (isDHCPEnabled(protType))
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        disableDHCP(protType);
    }

    HypIP::AddressOrigin origin = IP::AddressOrigin::Static;

    if (!isValidIP(AF_INET, ipaddress) && !isValidIP(AF_INET6, ipaddress))
    {
        log<level::ERR>("Not a valid IP address"),
            entry("ADDRESS=%s", ipaddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Address"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
        return sdbusplus::message::details::string_path_wrapper();
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
        return sdbusplus::message::details::string_path_wrapper();
    }

    const std::string ipObjId = "addr0";
    std::string protocol;
    if (protType == IP::Protocol::IPv4)
    {
        protocol = "ipv4";
    }
    else if (protType == IP::Protocol::IPv6)
    {
        protocol = "ipv6";
    }

    std::string objPath = objectPath + "/" + protocol + "/" + ipObjId;

    for (auto addr : addrs)
    {
        auto ipObj = addr.second;
        std::string ipObjAddr = ipObj->address();
        uint8_t ipObjPrefixLen = ipObj->prefixLength();
        std::string ipObjGateway = ipObj->gateway();

        if ((ipaddress == ipObjAddr) && (prefixLength == ipObjPrefixLen) &&
            (gateway == ipObjGateway))
        {
            log<level::ERR>("Trying to set same ip properties");
            // Return the existing object path
            return objPath;
        }
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        break;
    }

    addrs[ipaddress] = std::make_shared<phosphor::network::HypIPAddress>(
        bus, (objPath).c_str(), *this, protType, ipaddress, origin,
        prefixLength, gateway, intfLabel);

    PendingAttributesType pendingAttributes;

    auto ipObj = addrs[ipaddress];
    pendingAttributes.insert_or_assign(ipObj->mapDbusToBiosAttr("address"),
                                       std::make_tuple(biosStrType, ipaddress));
    pendingAttributes.insert_or_assign(ipObj->mapDbusToBiosAttr("gateway"),
                                       std::make_tuple(biosStrType, gateway));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("prefixLength"),
        std::make_tuple(biosIntType, prefixLength));

    ipObj->updateBiosPendingAttrs(pendingAttributes);

    return objPath;
}

HypEthernetIntf::DHCPConf
    HypEthInterface::dhcpEnabled(HypEthernetIntf::DHCPConf value)
{
    if (value == HypEthernetIntf::dhcpEnabled())
    {
        return value;
    }

    HypEthernetIntf::dhcpEnabled(value);

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        for (auto itr : addrs)
        {
            auto ipObj = itr.second;
            ipObj->resetIPObjProps();
            PendingAttributesType pendingAttributes;
            pendingAttributes.insert_or_assign(
                ipObj->mapDbusToBiosAttr("origin"),
                std::make_tuple(biosEnumType, "IPv4DHCP"));
            ipObj->updateBiosPendingAttrs(pendingAttributes);
            log<level::INFO>("Updating the ip address properties");
            dhcpCallbackMethod();
            break;
        }
    }
    else
    {
        for (auto itr : addrs)
        {
            auto ipObj = itr.second;
            PendingAttributesType pendingAttributes;
            pendingAttributes.insert_or_assign(
                ipObj->mapDbusToBiosAttr("origin"),
                std::make_tuple(biosEnumType, "IPv4Static"));
            ipObj->updateBiosPendingAttrs(pendingAttributes);
            ipObj->resetBaseBiosTableAttrs();
            ipObj->resetIPObjProps();
            break;
        }
    }

    return value;
}

} // namespace network
} // namespace phosphor
