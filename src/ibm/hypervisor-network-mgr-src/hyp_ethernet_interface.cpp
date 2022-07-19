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

bool HypEthInterface::isDHCPEnabled(HypIP::Protocol family)
{
    const auto cur = HypEthernetIntf::dhcpEnabled();
    return cur == HypEthInterface::DHCPConf::both ||
           (family == HypIP::Protocol::IPv6 &&
            cur == HypEthInterface::DHCPConf::v6) ||
           (family == HypIP::Protocol::IPv4 &&
            cur == HypEthInterface::DHCPConf::v4);
}

HypEthernetIntf::DHCPConf
    HypEthInterface::dhcpEnabled(HypEthernetIntf::DHCPConf value)
{
    if (value == HypEthernetIntf::dhcpEnabled())
    {
        return value;
    }

    HypEthernetIntf::dhcpEnabled(value);
    return value;
}

} // namespace network
} // namespace phosphor
