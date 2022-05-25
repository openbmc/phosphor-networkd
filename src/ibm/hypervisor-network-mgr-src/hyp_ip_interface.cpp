#include "hyp_ip_interface.hpp"

#include "types.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
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

template <typename T>
struct Proto
{};

template <>
struct Proto<stdplus::In4Addr>
{
    static inline constexpr auto value = HypIP::Protocol::IPv4;
};

template <>
struct Proto<stdplus::In6Addr>
{
    static inline constexpr auto value = HypIP::Protocol::IPv6;
};

HypIPAddress::HypIPAddress(sdbusplus::bus::bus& bus,
                           sdbusplus::message::object_path objPath,
                           stdplus::PinnedRef<HypEthInterface> parent,
                           stdplus::SubnetAny addr, const std::string& gateway,
                           HypIP::AddressOrigin origin,
                           const std::string& intf) :
    HypIPIfaces(bus, objPath.str.c_str(), HypIPIfaces::action::defer_emit),
    intf(std::move(intf)), parent(parent), objectPath(std::move(objPath))
{
    HypIP::address(stdplus::toStr(addr.getAddr()), true);
    HypIP::prefixLength(addr.getPfx(), true);
    HypIP::type(std::visit([](auto v) { return Proto<decltype(v)>::value; },
                           addr.getAddr()),
                true);
    HypIP::origin(origin, true);
    HypIP::gateway(gateway);

    std::string addressType;
    if (HypIP::type() == HypIP::Protocol::IPv4)
    {
        addressType = "ipv4";
    }
    else if (HypIP::type() == HypIP::Protocol::IPv6)
    {
        parent.get().HypEthernetIntf::defaultGateway6(gateway);
        addressType = "ipv6";
    }

    // De-serialize the persisted data and set the dbus property
    persistdata::deserialize(nwIPConfigList, intf, addressType);
    setEnabledProp();
    emit_object_added();
}

void HypIPAddress::setEnabledProp()
{
    auto itr = nwIPConfigList.find("Enabled");
    if (itr != nwIPConfigList.end())
    {
        HypIPAddress::enabled(std::get<bool>(itr->second));
    }
}

bool HypIPAddress::enabled(bool value)
{
    bool oldValue = HypEnableIntf::enabled();
    lg2::info(
        "Changing value of enabled property. Interface: {INTF}, Old Value: {OLDVAL}, New Value: {NEWVAL}",
        "INTF", intf, "OLDVAL", oldValue, "NEWVAL", value);

    if (value == oldValue)
    {
        return value;
    }

    HypEnableIntf::enabled(value);

    std::string propName = "Enabled";

    auto mapItr = nwIPConfigList.find(propName);

    if (mapItr != nwIPConfigList.end())
    {
        // Update the value of the key (Enabled) to true
        mapItr->second = value;
    }
    else
    {
        // Insert the key value pair (Enabled, true)
        nwIPConfigList.insert(std::pair<std::string, bool>(propName, value));
    }

    std::string type;
    if (HypIP::type() == HypIP::Protocol::IPv4)
    {
        type = "ipv4";
    }
    else if (HypIP::type() == HypIP::Protocol::IPv6)
    {
        type = "ipv6";
    }

    // serialize the data
    persistdata::serialize(nwIPConfigList, intf, type);
    return value;
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

    if (prefix.empty())
    {
        lg2::error("Invalid prefix: {PFX}", "PFX", prefix.c_str());
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
    lg2::info("Resetting the ip addr object properties");

    std::string defaultIp;
    uint8_t defaultPrefixLen = 0;
    std::string defaultMethod;
    if (HypIP::type() == HypIP::Protocol::IPv4)
    {
        defaultIp = "0.0.0.0";
        defaultMethod = "IPv4Static";
    }
    else if (HypIP::type() == HypIP::Protocol::IPv6)
    {
        defaultIp = "::";
        defaultPrefixLen = 128;
        defaultMethod = "IPv6Static";
        parent.get().HypEthernetIntf::defaultGateway6(defaultIp);
    }
    HypIP::address(defaultIp);
    HypIP::gateway(defaultIp);
    HypIP::prefixLength(defaultPrefixLen);
    HypIP::origin(HypIP::AddressOrigin::Static);

    std::string prefix = getHypPrefix();

    std::string attrIpaddr = prefix + "ipaddr";
    parent.get().setIpPropsInMap(attrIpaddr, defaultIp, "String");

    std::string attrGateway = prefix + "gateway";
    parent.get().setIpPropsInMap(attrGateway, defaultIp, "String");

    std::string attrPrefixLen = prefix + "prefix_length";
    parent.get().setIpPropsInMap(attrPrefixLen, defaultPrefixLen, "Integer");

    std::string attrMethod = prefix + "method";
    parent.get().setIpPropsInMap(attrMethod, defaultMethod, "String");
}

void HypIPAddress::resetBaseBiosTableAttrs(std::string protocol)
{
    // clear all the entries
    lg2::info("Resetting the bios table attrs of the ip object");

    if (protocol.empty())
    {
        protocol = convertProtocolToString(HypIP::type());
        protocol = protocol.substr(protocol.rfind(".") + 1);
    }

    std::string defaulAddr;
    std::string defaultGateway;
    int64_t defaultPrefLen;

    if (protocol == "IPv4")
    {
        defaulAddr = "0.0.0.0";
        defaultGateway = "0.0.0.0";
        defaultPrefLen = 0;
    }
    else if (protocol == "IPv6")
    {
        defaulAddr = "::";
        defaultGateway = "::";
        defaultPrefLen = 128;
    }
    updateBaseBiosTable(mapDbusToBiosAttr("address"), defaulAddr);
    updateBaseBiosTable(mapDbusToBiosAttr("gateway"), defaultGateway);
    updateBaseBiosTable(mapDbusToBiosAttr("prefixLength"), defaultPrefLen);
}

stdplus::InAnyAddr HypIPAddress::getIpAddress()
{
    try
    {
        switch (HypIP::type())
        {
            case HypIP::Protocol::IPv4:
                return stdplus::fromStr<stdplus::In4Addr>(HypIP::address());
            case HypIP::Protocol::IPv6:
                return stdplus::fromStr<stdplus::In6Addr>(HypIP::address());
            default:
                throw std::logic_error("Exhausted protocols");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Error in fetching IP: {ERROR}", "ERROR", e.what());
        elog<InternalFailure>();
    }
}

std::string HypIPAddress::address(std::string ipAddress)
{
    std::string ip = HypIP::address();
    if (ip == ipAddress)
    {
        return ip;
    }

    stdplus::InAnyAddr addr = getIpAddress();
    ipAddress = HypIP::address(stdplus::toStr(addr));

    // update the addrs map of parent object
    parent.get().updateIPAddress(ip, ipAddress);

    // update parent biosTableAttrs
    const std::string ipAttrName = "ipaddr";
    for (auto& it : parent.get().getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - ipAttrName.size(),
                              ipAttrName.size(), ipAttrName) == 0) &&
            (std::get<std::string>(it.second) == ip))
        {
            parent.get().setIpPropsInMap(it.first, ipAddress, "String");
        }
    }

    lg2::info("IP updated: {IPADDR}", "IPADDR", ipAddress);
    return ipAddress;
}

uint8_t HypIPAddress::prefixLength(uint8_t value)
{
    auto length = HypIP::prefixLength();
    if (value == length)
    {
        return length;
    }

    try
    {
        if (value == 0)
        {
            throw std::invalid_argument("default route");
        }
        value = HypIP::prefixLength(value);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX", value,
                   "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(value).c_str()));
    }

    // update parent biosTableAttrs
    const std::string prefixLenAttrName = "length";
    for (auto& it : parent.get().getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - prefixLenAttrName.size(),
                              prefixLenAttrName.size(),
                              prefixLenAttrName) == 0) &&
            (std::get<int64_t>(it.second) == length))
        {
            parent.get().setIpPropsInMap(it.first, value, "Integer");
        }
    }

    return value;
}

std::string HypIPAddress::gateway(std::string gateway)
{
    auto curr_gateway = HypIP::gateway();
    if (gateway == curr_gateway)
    {
        // value is already existing
        return gateway;
    }

    try
    {
        if (!gateway.empty())
        {
            auto protocol = HypIP::type();
            if (protocol == HypIP::Protocol::IPv4)
            {
                parent.get().validateGateway<stdplus::In4Addr>(gateway);
            }
            else if (protocol == HypIP::Protocol::IPv6)
            {
                parent.get().validateGateway<stdplus::In6Addr>(gateway);
                // update the default gw of the ethernet interface
                parent.get().defaultGateway6(gateway);
            }
        }
        else
        {
            throw std::invalid_argument("Empty gateway");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid Gateway: {GATEWAY}", "GATEWAY", gateway);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    gateway = HypIP::gateway(gateway);

    // update parent biosTableAttrs
    const std::string gatewayAttrName = this->getHypPrefix() + "gateway";
    for (auto& it : parent.get().getBiosAttrsMap())
    {
        if (it.first == gatewayAttrName)
        {
            parent.get().setIpPropsInMap(it.first, gateway, "String");
            updateBaseBiosTable(it.first, gateway);
            break;
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
        lg2::error("Not a valid origin");
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
    for (auto& it : parent.get().getBiosAttrsMap())
    {
        if ((it.first.compare(it.first.size() - originAttrName.size(),
                              originAttrName.size(), originAttrName) == 0) &&
            (std::get<std::string>(it.second) == currOriginValue))
        {
            parent.get().setIpPropsInMap(it.first, originBiosAttr, "String");
        }
    }

    return origin;
}

void HypIPAddress::delete_()
{
    if (HypIP::origin() != HypIP::AddressOrigin::Static)
    {
        lg2::error(
            "Tried to delete a non-static address. Address: {ADDR}, Prefix Length: {PREFIX}, Interface: {INTERFACE}",
            "ADDR", this->address(), "PREFIX", this->prefixLength(),
            "INTERFACE", this->parent.get().interfaceName());
        elog<InternalFailure>();
    }

    // update the ip address obj properties to null
    resetIPObjProps();

    // update bios table attrs to default
    if (HypIP::type() == HypIP::Protocol::IPv4)
    {
        resetBaseBiosTableAttrs("IPv4");
    }
    if (HypIP::type() == HypIP::Protocol::IPv6)
    {
        resetBaseBiosTableAttrs("IPv6");
    }
}

} // namespace network
} // namespace phosphor
