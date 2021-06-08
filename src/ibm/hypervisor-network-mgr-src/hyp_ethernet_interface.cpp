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

} // namespace network
} // namespace phosphor
