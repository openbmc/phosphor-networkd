#include "hyp_ethernet_interface.hpp"

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.getBIOSTableAttrs();
}

} // namespace network
} // namespace phosphor
