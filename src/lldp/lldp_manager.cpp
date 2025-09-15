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
using Property = std::variant<std::string, bool, uint8_t, int16_t, int32_t,
                              int64_t, uint16_t, uint32_t, uint64_t, double,
                              std::vector<std::string>>;

std::vector<std::string> Manager::getInterfaces()
{
    auto method = bus.new_method_call(
        "xyz.openbmc_project.Network", "/xyz/openbmc_project/network",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

    auto reply = bus.call(method);

    std::map<sdbusplus::message::object_path,
             std::map<std::string, std::map<std::string, Property>>>
        objects;

    reply.read(objects);

    std::vector<std::string> ifnames;
    for (const auto& [path, ifaces] : objects)
    {
        if (ifaces.find("xyz.openbmc_project.Network.EthernetInterface") !=
            ifaces.end())
        {
            ifnames.push_back(path.filename());
        }
    }
    return ifnames;
}

Manager::Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event,
                 const std::string& objPath) :
    bus(bus), event(event), objPath(objPath)
{
    auto interfaces = getInterfaces();
    for (const auto& ifname : interfaces)
    {
        std::string path = "/xyz/openbmc_project/network/lldp/" + ifname;

        neighbors[ifname] = std::make_unique<Neighbor>(bus, *this, path);

        lg2::info("Created Neighbor object for {IF} at {PATH}", "IF", ifname,
                  "PATH", path);
    }
}

} // namespace lldp
} // namespace network
} // namespace phosphor
