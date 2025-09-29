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
using phosphor::lldp_utils::LLDPUtils;

constexpr auto systemdBusname = "org.freedesktop.systemd1";
constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";
constexpr auto lldpFilePath = "/etc/lldpd.conf";
constexpr auto lldpService = "lldpd.service";

LLDPManager::LLDPManager(sdbusplus::bus_t& bus, sdeventplus::Event& event) :
    bus(bus), event(event)
{
    createIntfTimer = std::make_unique<
        sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>>(
        event,
        [this](auto& timer) {
            timer.setEnabled(false);
            this->createIntfDbusObjects();
        },
        std::chrono::seconds(0));

    createIntfTimer->setEnabled(true);
    configs = phosphor::lldp_utils::LLDPUtils::parseAllConfigs("/etc/lldpd.conf", "/etc/lldpd.d");
}

void LLDPManager::createIntfDbusObjects()
{
    auto interfaces = getInterfaces();
    for (const auto& ifname : interfaces)
    {
        if (ifaces.contains(ifname))
        {
            continue;
        }

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

void LLDPManager::handleLLDPEnableChange(const std::string& iface, bool enable)
{
    std::vector<std::string> matchPrefix = {
        "configure", "ports", iface, "lldp", "status"};

    bool updated = false;

    for (auto& entry : configs)
    {
        // Compare first n tokens with the prefix
        if (entry.size() >= matchPrefix.size() &&
            std::equal(matchPrefix.begin(), matchPrefix.end(), entry.begin()))
        {
            // Update existing status value (6th token)
            if (entry.size() > matchPrefix.size())
            {
                entry[matchPrefix.size()] = enable ? "rx-and-tx" : "disabled";
            }
            else
            {
                entry.push_back(enable ? "rx-and-tx" : "disabled");
            }

            updated = true;
            break;
        }
    }

    if (!updated)
    {
        // Add this new LLDP config line
        configs.push_back(matchPrefix);
        configs.back().push_back(enable ? "rx-and-tx" : "disabled");
    }

    std::string filePath = "/etc/lldpd.d/" + iface + ".conf";

    phosphor::lldp_utils::LLDPUtils::serialize(filePath, configs);

    // Reload lldpd to apply changes
    reloadLLDPService();
}

bool LLDPManager::isLLDPEnabledForInterface(const std::string& ifname) const
{
    std::vector<std::string> matchPrefix = {
        "configure", "ports", ifname, "lldp", "status"};

    for (const auto& entry : configs)
    {
        if (entry.size() > matchPrefix.size() &&
            std::equal(matchPrefix.begin(), matchPrefix.end(), entry.begin()))
        {
            const std::string& status = entry[matchPrefix.size()];
            return (status == "tx-only" || status == "rx-only" ||
                    status == "rx-and-tx");
        }
    }

    // Default: disabled if not found
    return false;
}

void LLDPManager::reloadLLDPService()
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
