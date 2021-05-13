#include "config.h"

#include "hyp_ip_interface.hpp"
#include "hyp_ethernet_interface.hpp"

#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using sdbusplus::exception::SdBusError;

class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

HypIPAddress::HypIPAddress(sdbusplus::bus::bus& bus, const char* objPath,
                           HypEthInterface& parent, HypIP::Protocol type,
                           const std::string& ipaddress, HypIP::AddressOrigin origin,
                           uint8_t prefixLength, const std::string& gateway, const std::string& intf) :
    HypIPIfaces(bus, objPath, true),
    parent(parent)
{
    HypIP::address(ipaddress);
    HypIP::prefixLength(prefixLength);
    HypIP::gateway(gateway);
    HypIP::type(type);
    HypIP::origin(origin);

    this->objectPath = objPath;
    this->intf = intf;
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

void HypIPAddress::updateBaseBiosTable(std::string attribute, std::variant<std::string, int64_t> attributeValue)
{
    auto bus = sdbusplus::bus::new_default();
    auto properties =
        bus.new_method_call("xyz.openbmc_project.BIOSConfigManager", "/xyz/openbmc_project/bios_config/manager",
                            "xyz.openbmc_project.BIOSConfig.Manager", "SetAttribute");
    properties.append(attribute);
    properties.append(attributeValue);
    auto result = bus.call(properties);

    if (result.is_method_error())
    {
        throw std::runtime_error("Set attribute api failed");
    }
}

void HypIPAddress::resetBaseBiosTableAttrs()
{
    std::string prefix = getHypPrefix();

    // clear all the entries
    updateBaseBiosTable(mapDbusToBiosAttr("address"), "0.0.0.0");
    updateBaseBiosTable(mapDbusToBiosAttr("gateway"), "0.0.0.0");
    updateBaseBiosTable(mapDbusToBiosAttr("prefixLength"), 0);
}

std::string HypIPAddress::address(std::string ipAddress)
{
    std::string ip = HypIP::address();
    if (ip == ipAddress)
    {
        log<level::INFO>("This value is already existing");
        return ip;
    }

    int addressFamily = (HypIP::type() == HypIP::Protocol::IPv4) ? AF_INET : AF_INET6;
    if (!isValidIP(addressFamily, ipAddress))
    {
        log<level::ERR>("Not a valid IP address"),
            entry("ADDRESS=%s", ipAddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Address"),
                              Argument::ARGUMENT_VALUE(ipAddress.c_str()));
    } 

    ipAddress = HypIP::address(ipAddress);

    // update the addrs map of parent object
    parent.updateIPAddress(ip, ipAddress);

    // update parent biosTableAttrs
    for (auto& it : parent.getBiosAttrsMap())
    {
        if (boost::ends_with(it.first, "ipaddr") && (std::get<std::string>(it.second) == ip))
        {
            parent.setIpPropsInMap(it.first, ipAddress, "String");
        }
    }

    // update the baseBiosTable
    updateBaseBiosTable(mapDbusToBiosAttr("address"), ipAddress);

    return ipAddress;
}

uint8_t HypIPAddress::prefixLength(uint8_t value)
{
    auto length = HypIP::prefixLength();
    if (value == length)
    {   
        log<level::INFO>("This value is already existing");
        return length;
    }
    int addressFamily = (HypIP::type() == HypIP::Protocol::IPv4) ? AF_INET : AF_INET6;
    if (!isValidPrefix(addressFamily, value))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%" PRIu8, value);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("PrefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(value).c_str()));
    }
    value = HypIP::prefixLength(value);

    // update parent biosTableAttrs
    for (auto& it : parent.getBiosAttrsMap())
    {
        if (boost::ends_with(it.first, "length") && (std::get<int64_t>(it.second) == length))
        {
            parent.setIpPropsInMap(it.first, value, "Integer");
        }
    }

    // update the baseBiosTable
    updateBaseBiosTable(mapDbusToBiosAttr("prefixLength"), value);
    return value;
}

std::string HypIPAddress::gateway(std::string gateway)
{
    auto gw = HypIP::gateway();

    if (gateway == gw)
    {
        log<level::INFO>("This value is already existing");
        return gw;
    }
    int addressFamily = (HypIP::type() == IP::Protocol::IPv4) ? AF_INET : AF_INET6;
    if (!isValidIP(addressFamily, gateway))
    {
        log<level::ERR>("Not a valid gateway"),
            entry("ADDRESS=%s", gateway.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Gateway"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    gateway = HypIP::gateway(gateway);

    // update parent biosTableAttrs
    for (auto& it : parent.getBiosAttrsMap())
    {
        if (boost::ends_with(it.first, "gateway") && (std::get<std::string>(it.second) == gw))
        {
            parent.setIpPropsInMap(it.first, gateway, "String");
        }
    }

    // update the baseBiosTable
    updateBaseBiosTable(mapDbusToBiosAttr("gateway"), gateway);

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
        log<level::INFO>("This value is already existing");
        return addrOrigin;
    }

    std::string originStr = convertAddressOriginToString(origin);
    std::string dhcpStr = convertAddressOriginToString(HypIP::AddressOrigin::DHCP);
    std::string staticStr = convertAddressOriginToString(HypIP::AddressOrigin::Static);

    if (originStr != dhcpStr && originStr != staticStr)
    {
        log<level::ERR>("Not a valid origin");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Origin"),
                              Argument::ARGUMENT_VALUE(originStr.c_str()));
    }

    origin = HypIP::origin(origin);

    std::string originBiosAttr;
    if (originStr.substr(originStr.rfind(".") + 1) == "Static")
    {
        originBiosAttr = "IPv4Static";
    }
    else if (originStr.substr(originStr.rfind(".") + 1) == "DHCP")
    {
        originBiosAttr = "IPv4DHCP";
    }

    std::string currOriginValue;
    if (addrOrigin == HypIP::AddressOrigin::Static)
    {
        currOriginValue = "IPv4Static";  
    }
    else if (addrOrigin == HypIP::AddressOrigin::DHCP)
    {
        currOriginValue = "IPv4DHCP";
    }

    // update parent biosTableAttrs
    for (auto& it : parent.getBiosAttrsMap())
    {
        if (boost::ends_with(it.first, "method") && (std::get<std::string>(it.second) == currOriginValue))
        {
            parent.setIpPropsInMap(it.first, originBiosAttr, "String");
        }
    }

    // update the baseBiosTable
    updateBaseBiosTable(mapDbusToBiosAttr("origin"), originBiosAttr);

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

    parent.deleteObject(this->address());

    // update bios table attrs to default
    //resetBaseBiosTableAttrs();
}

} // namespace network
} // namespace phosphor
