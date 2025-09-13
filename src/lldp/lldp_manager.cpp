#include "lldp_manager.hpp"

#include <arpa/inet.h>
#include <lldpctl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <phosphor-logging/lg2.hpp>

namespace phosphor
{
namespace network
{
namespace lldp
{

Manager::Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event,
                 const std::string& objPath) :
    bus(bus), event(event), objPath(objPath)
{}

} // namespace lldp
} // namespace network
} // namespace phosphor
