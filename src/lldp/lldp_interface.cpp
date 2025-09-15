#include "lldp_interface.hpp"

#include "lldp_manager.hpp"

namespace phosphor
{
namespace network
{
namespace lldp
{

Interface::Interface(sdbusplus::bus_t& bus, LLDPManager& manager,
                     const std::string& objPath, const std::string& ifname) :
    manager(manager), bus(bus), objPath(objPath), ifname(ifname)
{}

} // namespace lldp
} // namespace network
} // namespace phosphor
