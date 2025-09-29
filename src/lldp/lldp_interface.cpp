#include "lldp_interface.hpp"

#include "lldp_manager.hpp"

#include <lldpctl.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>

namespace phosphor
{
namespace network
{
namespace lldp
{

using namespace phosphor::logging;

constexpr auto systemdBusname = "org.freedesktop.systemd1";
constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";
constexpr auto lldpFilePath = "/etc/lldpd.conf";
constexpr auto lldpService = "lldpd.service";

static bool parseLLDPEnabledFromConfig(const std::string& ifname)
{
    std::ifstream infile(lldpFilePath);
    if (!infile.is_open())
    {
        lg2::warning("LLDP config file {PATH} not found", "PATH", lldpFilePath);
        return false;
    }

    std::string line;
    while (std::getline(infile, line))
    {
        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string word;
        while (iss >> word)
        {
            tokens.push_back(word);
        }

        // In config file, it looks like:
        // configure ports <ifname> lldp status <value>
        if (tokens.size() >= 6 && tokens[0] == "configure" &&
            tokens[1] == "ports" && tokens[2] == ifname &&
            tokens[3] == "lldp" && tokens[4] == "status")
        {
            std::string status = tokens[5];
            if (status == "disabled")
                return false;
            if (status == "tx-only" || status == "tx-and-rx" ||
                status == "rx-only")
                return true;
        }
    }

    return false;
}

void Interface::reloadLLDPService()
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

Interface::Interface(sdbusplus::bus_t& bus, Manager& manager,
                     const std::string& objPath, const std::string& ifname) :
    SettingsIface(bus, objPath.c_str(), SettingsIface::action::defer_emit),
    manager(manager), bus(bus), objPath(objPath), ifname(ifname)
{
    bool enabled = parseLLDPEnabledFromConfig(ifname);
    SettingsIface::enableLLDP(enabled);
    this->emit_object_added();
}

bool Interface::enableLLDP(bool value)
{
    bool curr = SettingsIface::enableLLDP();
    if (curr == value)
    {
        return value;
    }

    SettingsIface::enableLLDP(value);

    lg2::info("EnableLLDP changed on {IF}: {VAL}", "IF", ifname, "VAL",
              value ? "true" : "false");

    updateInterfaceLLDPConfig(value);

    return value;
}

std::string Interface::buildLLDPStatusCommand(bool enable) const
{
    return "configure ports " + ifname + " lldp status " +
           (enable ? "tx-and-rx" : "disabled");
}

void Interface::updateInterfaceLLDPConfig(bool enable)
{
    std::ifstream inFile(lldpFilePath);
    std::vector<std::string> lines;
    bool updated = false;

    if (inFile.is_open())
    {
        std::string line;
        while (std::getline(inFile, line))
        {
            if (line.find("configure ports " + ifname + " lldp status") == 0)
            {
                lines.push_back(buildLLDPStatusCommand(enable));
                updated = true;
            }
            else
            {
                lines.push_back(line);
            }
        }
        inFile.close();
    }

    if (!updated)
    {
        lines.push_back(buildLLDPStatusCommand(enable));
    }

    std::ofstream outFile(lldpFilePath, std::ios::trunc);
    if (!outFile.is_open())
    {
        lg2::error("Failed to open {PATH} to update LLDP config", "PATH",
                   lldpFilePath);
        return;
    }

    for (const auto& l : lines)
        outFile << l << "\n";

    lg2::info("Updated LLDP config for interface {IF}: {STATE}", "IF", ifname,
              "STATE", (enable ? "tx-and-rx" : "disabled"));
    reloadLLDPService();
}

} // namespace lldp
} // namespace network
} // namespace phosphor
