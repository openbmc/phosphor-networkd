#include "hyp_ethernet_interface.hpp"

#include <boost/algorithm/string.hpp>

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

std::shared_ptr<phosphor::network::HypIPAddress>
    HypEthInterface::getIPAddrObject(std::string attrName,
                                     std::string oldIpAddr = "")
{
    auto biosTableAttrs = manager.getBIOSTableAttrs();
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr == biosTableAttrs.end())
    {
        log<level::ERR>("Attribute not found in the list");
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
    manager.setBIOSTableAttrs(attrName, attrValue, attrType);
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
        deleteObject(ip);
        addrs.emplace(updatedIp, ipObj);
        log<level::INFO>("Successfully updated ip address");
        return;
    }
}

void HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        log<level::ERR>("DeleteObject:Unable to find the object.");
        return;
    }
    addrs.erase(it);
    log<level::INFO>("Successfully deleted the ip address object");
}

std::string HypEthInterface::getIntfLabel()
{
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
            if (boost::contains(ipType, "Static"))
            {
                ipOrigin = IP::AddressOrigin::Static;
            }
            else if (boost::contains(ipType, "DHCP"))
            {
                ipOrigin = IP::AddressOrigin::DHCP;
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
    }

    for (auto addr : addrs)
    {
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        auto ipObj = addr.second;
        break;
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
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
            ipObj->resetBaseBiosTableAttrs();
            PendingAttributesType pendingAttributes;
            pendingAttributes.insert_or_assign(
                ipObj->mapDbusToBiosAttr("origin"),
                std::make_tuple(biosEnumType, "IPv4DHCP"));
            ipObj->updateBiosPendingAttrs(pendingAttributes);
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
        }
    }

    return value;
}

} // namespace network
} // namespace phosphor
