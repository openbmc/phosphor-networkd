#include "lldp_interface.hpp"
#include "lldp_manager.hpp"

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <functional>

namespace phosphor
{
namespace network
{
namespace lldp
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using NotAllowed = sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;

Interface::Interface(sdbusplus::bus_t& bus, Manager& manager, const std::string& objPath,
                     const std::string& ifname) :
    manager(manager), busRef(bus), objPath(objPath), ifname(ifname)
{}

} // namespace lldp
} // namespace network
} // namespace phosphor

