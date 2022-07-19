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

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.getBIOSTableAttrs();
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

bool HypEthInterface::dhcpIsEnabled(IP::Protocol family)
{
    switch (family)
    {
        case IP::Protocol::IPv6:
            return dhcp6();
        case IP::Protocol::IPv4:
            return dhcp4();
    }
    throw std::logic_error("Unreachable");
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

    if (old4 != new4 || old6 != new6 || oldra != newra)
    {
        HypEthernetIntf::dhcpEnabled(value);
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
        return ipv6AcceptRA() ? DHCPConf::v4v6stateless : DHCPConf::v4;
    }
    return ipv6AcceptRA() ? DHCPConf::v6stateless : DHCPConf::none;
}

} // namespace network
} // namespace phosphor
