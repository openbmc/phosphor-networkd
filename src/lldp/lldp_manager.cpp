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

LLDPManager::LLDPManager(sdbusplus::bus_t& bus, sdeventplus::Event& event) :
    bus(bus), event(event)
{
    createIntfTimer = std::make_unique<
        sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>>(
        event, [this](auto&) { this->createIntfDbusObjects(); },
        std::chrono::seconds(0));

    createIntfTimer->setEnabled(true);
}

void LLDPManager::createIntfDbusObjects()
{
    auto interfaces = getInterfaces();
    for (auto ifname : interfaces)
    {
        const std::string path = std::string(objPath) + "/" + ifname;
        ifaces.emplace(ifname,
                       std::make_unique<Interface>(bus, *this, path, ifname));
        lg2::info("Created Interface object for {IF} at {PATH}", "IF", ifname,
                  "PATH", path);
    }
}

std::vector<std::string> LLDPManager::getInterfaces()
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

} // namespace lldp
} // namespace network
} // namespace phosphor
