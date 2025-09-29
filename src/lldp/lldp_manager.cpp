#include "lldp_manager.hpp"

#include "lldp_interface.hpp"

#include <arpa/inet.h>
#include <lldpctl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message/types.hpp>
#include <sdbusplus/server.hpp>

#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
namespace lldp
{

using DBusProp = std::variant<std::string, bool, uint8_t, int16_t, int32_t,
                              int64_t, uint16_t, uint32_t, uint64_t, double,
                              std::vector<std::string>>;

constexpr auto systemdBusname = "org.freedesktop.systemd1";
constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";
constexpr auto lldpFilePath = "/etc/lldpd.conf";
constexpr auto lldpService = "lldpd.service";

Manager::Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event,
                 const std::string& objPath) :
    bus(bus), event(event), objPath(objPath)
{
    auto interfaces = getInterfaces();
    for (auto ifname : interfaces)
    {
        const std::string path = objPath + "/" + ifname;
        ifaces.emplace(ifname,
                       std::make_unique<Interface>(bus, *this, path, ifname));
        lg2::info("Created Interface object for {IF} at {PATH}", "IF", ifname,
                  "PATH", path);
    }
}

std::vector<std::string> Manager::getInterfaces()
{
    std::vector<std::string> ifnames;

    try
    {
        auto method = bus.new_method_call(
            "xyz.openbmc_project.Network", "/xyz/openbmc_project/network",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        auto reply = bus.call(method);

        std::map<sdbusplus::message::object_path,
                 std::map<std::string, std::map<std::string, DBusProp>>>
            objects;

        reply.read(objects);

        for (const auto& [path, ifacesMap] : objects)
        {
            if (ifacesMap.find(
                    "xyz.openbmc_project.Network.EthernetInterface") !=
                ifacesMap.end())
            {
                ifnames.push_back(path.filename());
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to call GetManagedObjects: {ERR}", "ERR", e.what());
    }

    return ifnames;
}

void Manager::reloadLLDPService()
{
    try
    {
        auto method = bus.new_method_call(systemdBusname, systemdObjPath,
                                          systemdInterface, "RestartUnit");
        method.append(lldpService, "replace");
        bus.call_noreply(method);

        lg2::info("Requested restart of {SERVICE}", "SERVICE", lldpService);
    }
    catch (const sdbusplus::exception_t& ex)
    {
        lg2::error("Failed to restart service {SERVICE}: {ERR}", "SERVICE",
                   lldpService, "ERR", ex);
    }
}

} // namespace lldp
} // namespace network
} // namespace phosphor
