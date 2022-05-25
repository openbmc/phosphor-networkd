#include "hyp_ip_interface.hpp"

#include "hyp_ethernet_interface.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedArgument = xyz::openbmc_project::Common::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

HypIPAddress::HypIPAddress(sdbusplus::bus::bus& bus, const char* objPath,
                           HypEthInterface& parent, HypIP::Protocol type,
                           const std::string& ipaddress,
                           HypIP::AddressOrigin origin, uint8_t prefixLength,
                           const std::string& gateway,
                           const std::string& intf) :
    HypIPIfaces(bus, objPath, HypIPIfaces::action::defer_emit),
    parent(parent)
{
    HypIP::address(ipaddress);
    HypIP::prefixLength(prefixLength);
    HypIP::gateway(gateway);
    HypIP::type(type);
    HypIP::origin(origin);

    this->objectPath = objPath;
    this->intf = intf;

    setEnabledProp();
}

void HypIPAddress::setEnabledProp()
{
    std::string enabledPropKey;

    if (this->type() == HypIP::Protocol::IPv4)
    {
        enabledPropKey = "v4Enabled";
    }
    else if (this->type() == HypIP::Protocol::IPv6)
    {
        enabledPropKey = "v6Enabled";
    }

    NwConfigPropMap& nwIPConfigList = parent.getNwConfigPropMap();

    auto itr = nwIPConfigList.find(enabledPropKey);
    if (itr != nwIPConfigList.end())
    {
        HypIPAddress::enabled(std::get<bool>(itr->second));
    }
}

bool HypIPAddress::enabled(bool value)
{
    bool oldValue = HypEnableIntf::enabled();
    log<level::INFO>("Changing value of enabled property",
                     entry("INTERFACE=%s", intf.c_str()),
                     entry("OLDVALUE=%d", oldValue), entry("VALUE=%d", value));

    if (value == oldValue)
    {
        return value;
    }

    HypEnableIntf::enabled(value);

    std::string prot;
    if (this->type() == HypIP::Protocol::IPv4)
    {
        prot = "v4";
    }
    else if (this->type() == HypIP::Protocol::IPv6)
    {
        prot = "v6";
    }
    std::string propName = prot + "Enabled";

    NwConfigPropMap& nwIPConfigList = parent.getNwConfigPropMap();
    auto mapItr = nwIPConfigList.find(propName);

    if (mapItr != nwIPConfigList.end())
    {
        // Update the value of the key (Enabled) to true
        mapItr->second = value;
    }
    else
    {
        // Insert the key value pair (Enabled, true)
        nwIPConfigList.emplace(std::pair<std::string, bool>(propName, value));
    }
    // serialize the data
    persistdata::serialize(nwIPConfigList, intf);
    return value;
}

std::string HypIPAddress::getObjPath()
{
    return objectPath;
}

std::string HypIPAddress::getHypPrefix()
{
    std::string protocol = convertProtocolToString(HypIP::type());
    protocol = protocol.substr(protocol.rfind(".") + 1);

    if (protocol == "IPv4")
    {
        return "vmi_" + this->intf + "_ipv4_";
    }
    else if (protocol == "IPv6")
    {
        return "vmi_" + this->intf + "_ipv6_";
    }
    return "";
}

std::string HypIPAddress::mapDbusToBiosAttr(std::string dbusProp)
{
    std::string prefix = getHypPrefix();

    if (prefix == "")
    {
        log<level::ERR>("Not a valid prefix"),
            entry("ADDRESS=%s", prefix.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Prefix"),
                              Argument::ARGUMENT_VALUE(prefix.c_str()));
    }

    if (dbusProp == "address")
    {
        prefix = prefix + "ipaddr";
    }
    else if (dbusProp == "gateway")
    {
        prefix = prefix + "gateway";
    }
    else if (dbusProp == "origin")
    {
        prefix = prefix + "method";
    }
    else if (dbusProp == "prefixLength")
    {
        prefix = prefix + "prefix_length";
    }
    return prefix;
}

void HypIPAddress::updateBaseBiosTable(
    std::string attribute, std::variant<std::string, int64_t> attributeValue)
{
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.BIOSConfigManager",
        "/xyz/openbmc_project/bios_config/manager",
        "xyz.openbmc_project.BIOSConfig.Manager", "SetAttribute");
    properties.append(attribute);
    properties.append(attributeValue);
    auto result = bus.call(properties);

    if (result.is_method_error())
    {
        throw std::runtime_error("Set attribute api failed");
    }
}

void HypIPAddress::updateBiosPendingAttrs(
    PendingAttributesType pendingAttributes)
{
    auto bus = sdbusplus::bus::new_default();

    auto properties =
        bus.new_method_call("xyz.openbmc_project.BIOSConfigManager",
                            "/xyz/openbmc_project/bios_config/manager",
                            "org.freedesktop.DBus.Properties", "Set");
    properties.append("xyz.openbmc_project.BIOSConfig.Manager");
    properties.append("PendingAttributes");
    properties.append(std::variant<PendingAttributesType>(pendingAttributes));
    auto result = bus.call(properties);

    if (result.is_method_error())
    {
        throw std::runtime_error("Set attribute api failed");
    }
}

void HypIPAddress::resetIPObjProps()
{
    // Reset the ip obj properties
    log<level::INFO>("Resetting the ip addr object properties");

    std::string zeroIp = "0.0.0.0";
    HypIP::address(zeroIp);
    HypIP::gateway(zeroIp);
    HypIP::prefixLength(0);
    HypIP::origin(IP::AddressOrigin::Static);

    std::string prefix = getHypPrefix();

    std::string attrIpaddr = prefix + "ipaddr";
    parent.setIpPropsInMap(attrIpaddr, zeroIp, "String");

    std::string attrPrefixLen = prefix + "prefix_length";
    parent.setIpPropsInMap(attrPrefixLen, 0, "Integer");

    std::string attrGateway = prefix + "gateway";
    parent.setIpPropsInMap(attrGateway, zeroIp, "String");

    std::string attrMethod = prefix + "method";
    if (HypIP::type() == HypIP::Protocol::IPv4)
    {
        parent.setIpPropsInMap(attrMethod, "IPv4Static", "String");
    }
    else if (HypIP::type() == HypIP::Protocol::IPv6)
    {
        parent.setIpPropsInMap(attrMethod, "IPv6Static", "String");
    }
}

void HypIPAddress::resetBaseBiosTableAttrs()
{
    // clear all the entries
    log<level::INFO>("Resetting the bios table attrs of the ip object");

    std::string defaulAddr;
    std::string defaultGateway;
    int64_t defaultPrefLen;

    if (HypIP::type() == HypIP::Protocol::IPv4)
    {
        defaulAddr = "0.0.0.0";
        defaultGateway = "0.0.0.0";
        defaultPrefLen = 0;
    }
    else if (HypIP::type() == HypIP::Protocol::IPv6)
    {
        defaulAddr = "::";
        defaultGateway = "::";
        defaultPrefLen = 128;
    }
    updateBaseBiosTable(mapDbusToBiosAttr("address"), defaulAddr);
    updateBaseBiosTable(mapDbusToBiosAttr("gateway"), defaultGateway);
    updateBaseBiosTable(mapDbusToBiosAttr("prefixLength"), defaultPrefLen);
}

std::string HypIPAddress::address(std::string ipAddress)
{
    std::string ip = HypIP::address();
    if (ip == ipAddress)
    {
        return ip;
    }

    int addressFamily =
        (HypIP::type() == HypIP::Protocol::IPv4) ? AF_INET : AF_INET6;
    if (!isValidIP(addressFamily, ipAddress))
    {
        log<level::ERR>("Not a valid IP address"),
            entry("ADDRESS=%s", ipAddress.c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON("Invalid Ip"));
    }

    log<level::INFO>("IP updated"), entry("ADDRESS=%s", ipAddress.c_str());
    ipAddress = HypIP::address(ipAddress);

    // update the addrs map of parent object
    parent.updateIPAddress(ip, ipAddress);

    // update parent biosTableAttrs
    const std::string ipAttrName = "ipaddr";
    for (auto& it : parent.getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - ipAttrName.size(),
                              ipAttrName.size(), ipAttrName) == 0) &&
            (std::get<std::string>(it.second) == ip))
        {
            parent.setIpPropsInMap(it.first, ipAddress, "String");
        }
    }

    return ipAddress;
}

uint8_t HypIPAddress::prefixLength(uint8_t value)
{
    auto length = HypIP::prefixLength();
    if (value == length)
    {
        return length;
    }
    int addressFamily =
        (HypIP::type() == HypIP::Protocol::IPv4) ? AF_INET : AF_INET6;
    if (!isValidPrefix(addressFamily, value))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%" PRIu8, value);
        elog<NotAllowed>(NotAllowedArgument::REASON("Invalid Prefixlength"));
    }
    value = HypIP::prefixLength(value);

    // update parent biosTableAttrs
    const std::string prefixLenAttrName = "length";
    for (auto& it : parent.getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - prefixLenAttrName.size(),
                              prefixLenAttrName.size(),
                              prefixLenAttrName) == 0) &&
            (std::get<int64_t>(it.second) == length))
        {
            parent.setIpPropsInMap(it.first, value, "Integer");
        }
    }

    return value;
}

std::string HypIPAddress::gateway(std::string gateway)
{
    auto gw = HypIP::gateway();

    if (gateway == gw)
    {
        // value is already existing
        return gw;
    }
    int addressFamily =
        (HypIP::type() == IP::Protocol::IPv4) ? AF_INET : AF_INET6;
    if (!isValidIP(addressFamily, gateway))
    {
        log<level::ERR>("Not a valid gateway"),
            entry("ADDRESS=%s", gateway.c_str());
        elog<NotAllowed>(NotAllowedArgument::REASON("Invalid Gateway"));
    }

    gateway = HypIP::gateway(gateway);

    // update parent biosTableAttrs
    const std::string gatewayAttrName = "gateway";
    for (auto& it : parent.getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - gatewayAttrName.size(),
                              gatewayAttrName.size(), gatewayAttrName) == 0) &&
            (std::get<std::string>(it.second) == gw))
        {
            parent.setIpPropsInMap(it.first, gateway, "String");
        }
    }

    return gateway;
}

HypIP::Protocol HypIPAddress::type(HypIP::Protocol /*type*/)
{
    elog<NotAllowed>(Reason("Property update is not allowed"));
}

HypIP::AddressOrigin HypIPAddress::origin(HypIP::AddressOrigin origin)
{
    auto addrOrigin = HypIP::origin();
    if (origin == addrOrigin)
    {
        // value is already existing
        return addrOrigin;
    }

    std::string originStr = convertAddressOriginToString(origin);
    std::string dhcpStr =
        convertAddressOriginToString(HypIP::AddressOrigin::DHCP);
    std::string staticStr =
        convertAddressOriginToString(HypIP::AddressOrigin::Static);

    if (originStr != dhcpStr && originStr != staticStr)
    {
        log<level::ERR>("Not a valid origin");
        elog<NotAllowed>(NotAllowedArgument::REASON("Invalid Origin"));
    }

    std::string originBiosAttr;
    if (originStr.substr(originStr.rfind(".") + 1) == "Static")
    {
        if (HypIP::type() == HypIP::Protocol::IPv4)
        {
            originBiosAttr = "IPv4Static";
        }
        else if (HypIP::type() == HypIP::Protocol::IPv6)
        {
            originBiosAttr = "IPv6Static";
        }
    }
    else if (originStr.substr(originStr.rfind(".") + 1) == "DHCP")
    {
        if (HypIP::type() == HypIP::Protocol::IPv4)
        {
            originBiosAttr = "IPv4DHCP";
        }
        else if (HypIP::type() == HypIP::Protocol::IPv6)
        {
            originBiosAttr = "IPv6DHCP";
        }
    }

    std::string currOriginValue;
    if (addrOrigin == HypIP::AddressOrigin::Static)
    {
        if (HypIP::type() == HypIP::Protocol::IPv4)
        {
            currOriginValue = "IPv4Static";
        }
        else if (HypIP::type() == HypIP::Protocol::IPv6)
        {
            currOriginValue = "IPv6Static";
        }
    }
    else if (addrOrigin == HypIP::AddressOrigin::DHCP)
    {
        if (HypIP::type() == HypIP::Protocol::IPv4)
        {
            currOriginValue = "IPv4DHCP";
        }
        else if (HypIP::type() == HypIP::Protocol::IPv6)
        {
            currOriginValue = "IPv6DHCP";
        }
    }

    origin = HypIP::origin(origin);

    // update parent biosTableAttrs
    const std::string originAttrName = "method";
    for (auto& it : parent.getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - originAttrName.size(),
                              originAttrName.size(), originAttrName) == 0) &&
            (std::get<std::string>(it.second) == currOriginValue))
        {
            parent.setIpPropsInMap(it.first, originBiosAttr, "String");
        }
    }

    return origin;
}

void HypIPAddress::delete_()
{
    if (HypIP::origin() != HypIP::AddressOrigin::Static)
    {
        log<level::ERR>("Tried to delete a non-static address"),
            entry("ADDRESS=%s", this->address().c_str()),
            entry("PREFIX=%" PRIu8, this->prefixLength()),
            entry("INTERFACE=%s", this->parent.interfaceName().c_str());
        elog<InternalFailure>();
    }

    // update the ip address obj properties to null
    resetIPObjProps();

    // update bios table attrs to default
    resetBaseBiosTableAttrs();
}

} // namespace network
} // namespace phosphor
