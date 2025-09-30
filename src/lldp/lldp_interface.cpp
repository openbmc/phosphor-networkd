#include "lldp_interface.hpp"

#include "lldp_manager.hpp"

#include <arpa/inet.h>
#include <lldpctl.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
    // create transmit dbus object once
    transmit = std::make_unique<TLVs>(bus, objPath + "/transmit");

    bool enabled = parseLLDPEnabledFromConfig(ifname);
    SettingsIface::enableLLDP(enabled);
    if (enabled)
    {
        refreshInterface();
    }
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

    if (value)
    {
        refreshInterface();
    }
    else
    {
        if (receive)
        {
            lg2::info("Removing \"receive\" object on {IF}", "IF", ifname);
            receive.reset();
        }
    }

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

void Interface::updateTransmitObjProperties()
{
    // TODO: Read the transmit properties using lldpctl APIs
    // and set it to the transmit obj properties
}

void Interface::refreshInterface()
{
    auto* conn = lldpctl_new_name(lldpctl_get_default_transport(), nullptr,
                                  nullptr, nullptr);
    if (!conn)
    {
        lg2::error("Could not connect to lldpd daemon");
        return;
    }

    lldpctl_atom_t* ports = lldpctl_get_interfaces(conn);
    if (!ports)
    {
        lg2::info("lldpctl: no ports");
        lldpctl_release(conn);
        return;
    }

    lldpctl_atom_t* port = nullptr;
    lldpctl_atom_foreach(ports, port)
    {
        lldpctl_atom_t* p = lldpctl_get_port(port);
        if (!p)
            continue;

        const char* pname = lldpctl_atom_get_str(p, lldpctl_k_port_name);
        if (!pname || ifname != pname)
        {
            lldpctl_atom_dec_ref(p);
            continue;
        }

        lldpctl_atom_t* neighbors =
            lldpctl_atom_get(p, lldpctl_k_port_neighbors);
        if (!neighbors)
        {
            lldpctl_atom_dec_ref(p);
            break;
        }

        lldpctl_atom_t* neigh = nullptr;
        lldpctl_atom_foreach(neighbors, neigh)
        {
            const char* chassis =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_id);
            const char* portid = lldpctl_atom_get_str(neigh, lldpctl_k_port_id);
            const char* sysname =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_name);
            const char* sysdesc =
                lldpctl_atom_get_str(neigh, lldpctl_k_chassis_descr);

            std::string mgmtV4;
            std::string mgmtV6;
            lldpctl_atom_t* mgmts =
                lldpctl_atom_get(neigh, lldpctl_k_chassis_mgmt);
            if (mgmts)
            {
                lldpctl_atom_t* mgmt = nullptr;
                lldpctl_atom_foreach(mgmts, mgmt)
                {
                    const char* mip =
                        lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip);
                    if (mip && *mip)
                    {
                        in_addr addr4;
                        in6_addr addr6;
                        if (inet_pton(AF_INET, mip, &addr4) == 1)
                            mgmtV4 = mip;
                        else if (inet_pton(AF_INET6, mip, &addr6) == 1)
                            mgmtV6 = mip;
                    }
                }
                lldpctl_atom_dec_ref(mgmts);
            }

            updateOrCreateNeighborRx(
                chassis ? std::string(chassis) : std::string(),
                portid ? std::string(portid) : std::string(),
                sysname ? std::string(sysname) : std::string(),
                sysdesc ? std::string(sysdesc) : std::string(), mgmtV4, mgmtV6);
        }

        lldpctl_atom_dec_ref(neighbors);
        lldpctl_atom_dec_ref(p);
        break;
    }

    lldpctl_atom_dec_ref(ports);
    lldpctl_release(conn);
}

void Interface::updateOrCreateNeighborRx(
    const std::string& chassisId, const std::string& portId,
    const std::string& sysName, const std::string& sysDesc,
    const std::string& mgmtIPv4, const std::string& mgmtIPv6)
{
    if (receive)
    {
        TLVs& tlv = *receive;
        if (!chassisId.empty())
            tlv.setChassisId(chassisId);
        if (!portId.empty())
            tlv.setPortId(portId);
        if (!sysName.empty())
            tlv.setSystemName(sysName);
        if (!sysDesc.empty())
            tlv.setSystemDescription(sysDesc);
        if (!mgmtIPv4.empty())
            tlv.setManagementAddressIPv4(mgmtIPv4);
        if (!mgmtIPv6.empty())
            tlv.setManagementAddressIPv6(mgmtIPv6);
        return;
    }

    std::string path = objPath + "/receive";

    lg2::info("Creating \"receive\" dbus object on {IF} at {PATH}", "IF",
              ifname, "PATH", path);

    try
    {
        auto tlvObj = std::make_unique<TLVs>(bus, path);
        if (!chassisId.empty())
            tlvObj->setChassisId(chassisId);
        if (!portId.empty())
            tlvObj->setPortId(portId);
        if (!sysName.empty())
            tlvObj->setSystemName(sysName);
        if (!sysDesc.empty())
            tlvObj->setSystemDescription(sysDesc);
        if (!mgmtIPv4.empty())
            tlvObj->setManagementAddressIPv4(mgmtIPv4);
        if (!mgmtIPv6.empty())
            tlvObj->setManagementAddressIPv6(mgmtIPv6);
        receive = std::move(tlvObj);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to create \"receive\" dbus object. Error: {ERR}",
                   "ERR", e.what());
    }
}

} // namespace lldp
} // namespace network
} // namespace phosphor
