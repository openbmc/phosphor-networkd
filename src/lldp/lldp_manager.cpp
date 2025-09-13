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

LLDPManager::LLDPManager(sdbusplus::bus_t& bus, sdeventplus::Event& event) :
    bus(bus), event(event)
{}

} // namespace lldp
} // namespace network
} // namespace phosphor
