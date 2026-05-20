#include "bond.hpp"

#include "config_parser.hpp"
#include "ethernet_interface.hpp"
#include "network_manager.hpp"
#include "system_queries.hpp"
#include "util.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using REASON =
    phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using phosphor::logging::elog;

using Argument =
    phosphor::logging::xyz::openbmc_project::Common::InvalidArgument;

constexpr auto IPMI_CHANNEL_CONFIG =
    "/usr/share/ipmi-providers/channel_config.json";

static auto makeObjPath(std::string_view root)
{
    auto ret = sdbusplus::message::object_path(std::string(root));
    return ret;
}

Bond::Bond(sdbusplus::bus_t& bus, std::string_view objRoot,
           EthernetInterface& eth, std::string activeSlave, uint8_t miiMonitor,
           Mode mode) :
    Bond(bus, makeObjPath(objRoot), eth, activeSlave, miiMonitor, mode)
{}

Bond::Bond(sdbusplus::bus_t& bus, sdbusplus::message::object_path objPath,
           EthernetInterface& eth, std::string activeSlave, uint8_t miiMonitor,
           Mode mode) :
    BondObj(bus, objPath.str.c_str(), BondObj::action::defer_emit), eth(eth),
    objPath(std::move(objPath))
{
    BondIntf::activeSlave(activeSlave, true);
    BondIntf::miiMonitor(miiMonitor, true);
    BondIntf::mode(mode, true);
    emit_object_added();
}

void Bond::delete_()
{
    auto intf = eth.interfaceName();
    // Remove all configs for the current interface
    const auto& confDir = eth.manager.get().getConfDir();
    std::error_code ec;

    auto it = eth.manager.get().interfaces.find(intf);
    auto obj = std::move(it->second);
    eth.manager.get().interfaces.erase(it);

    eth.manager.get().writeToConfigurationFile();
    writeBondConfiguration(false);
    std::filesystem::remove(config::pathForIntfConf(confDir, intf), ec);
    std::filesystem::remove(config::pathForIntfDev(confDir, intf), ec);

    execute("/bin/systemctl", "systemctl", "stop",
            "phosphor-ipmi-net@bond0.service");

    execute("/bin/systemctl", "systemctl", "restart",
            "systemd-networkd.service");

    sleep(3);

    for (auto it = eth.manager.get().interfaces.begin();
         it != eth.manager.get().interfaces.end(); it++)
    {
        execute("/bin/systemctl", "systemctl", "restart",
                fmt::format("phosphor-ipmi-net@{}.service",
                            it->second->interfaceName())
                    .c_str());
    }

    eth.manager.get().reloadConfigs();
}

std::string Bond::activeSlave(std::string activeSlave)
{
    auto it = eth.manager.get().interfaces.find(activeSlave);
    if (it == eth.manager.get().interfaces.end())
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ActiveSlave"),
                              Argument::ARGUMENT_VALUE(activeSlave.c_str()));
    }
    else if (activeSlave.compare("bond0") == 0)
    {
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ActiveSlave"),
                              Argument::ARGUMENT_VALUE(activeSlave.c_str()));
    }

    if (BondIntf::activeSlave() != activeSlave)
    {
        BondIntf::activeSlave(activeSlave);
        [[maybe_unused]] auto rc = std::system(
            fmt::format(
                "/bin/echo {} > /sys/class/net/bond0/bonding/active_slave",
                activeSlave.c_str())
                .c_str());
    }
    return BondIntf::activeSlave();
}
uint8_t Bond::miiMonitor(uint8_t /*MIIMonitor*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}
Bond::Mode Bond::mode(Mode /*Bonding Mode*/)
{
    elog<NotAllowed>(REASON("Property update is not allowed"));
}

void Bond::writeBondConfiguration(bool isActive)
{
    const auto& confDir = eth.manager.get().getConfDir();
    std::ofstream ofs;
    std::ifstream ifs, tmpIfs;
    std::string intfName;
    std::string line;

    if (isActive)
    {
        // Read FROM backup, write TO bond0
        ifs.open(config::pathForIntfConf(
            eth.manager.get().getBondingConfBakDir(), BondIntf::activeSlave()));
        if (!ifs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration slave configuration file not opened.\n");
        }

        ofs.open(config::pathForIntfConf(confDir, "bond0"));
        if (!ofs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration bond configuration file not opened.\n");
        }

        intfName = "Name=bond0";
    }
    else
    {
        // Read FROM bond0, write TO primary slave
        ifs.open(config::pathForIntfConf(confDir, "bond0"));
        if (!ifs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration slave configuration file not opened.\n");
        }

        tmpIfs.open("/sys/class/net/bond0/bonding/primary", std::ifstream::in);
        if (!tmpIfs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration primary slave file not opened.\n");
        }

        std::string tmp;
        std::getline(tmpIfs, tmp);
        tmpIfs.close();

        ofs.open(config::pathForIntfConf(confDir, tmp));
        if (!ofs.is_open())
        {
            log<level::INFO>(
                "writeBondConfiguration bond configuration file not opened.\n");
        }

        intfName = std::format("Name={}", tmp);
    }

    while (ifs.peek() != EOF)
    {
        std::getline(ifs, line);
        if (line.starts_with("Name="))
        {
            ofs << intfName << std::endl;
        }
        else
        {
            ofs << line << std::endl;
        }
        line.clear();
    }

    ofs.flush();
    ofs.close();
    ifs.close();

    auto readJsonFile =
        [](const std::string& configFile) -> nlohmann::ordered_json {
        std::ifstream jsonFile(configFile);
        if (!jsonFile.good())
        {
            log<level::ERR>("JSON file not found");
            return nullptr;
        }

        nlohmann::ordered_json data = nullptr;
        try
        {
            data = nlohmann::ordered_json::parse(jsonFile, nullptr, false);
        }
        catch (nlohmann::ordered_json::parse_error& e)
        {
            log<level::ERR>("Corrupted channel config.");
            throw std::runtime_error("Corrupted channel config file");
        }

        return data;
    };

    auto writeJsonFile = [](const std::string& configFile,
                            const nlohmann::ordered_json& jsonData) {
        std::ofstream jsonFile(configFile);
        if (!jsonFile.good())
        {
            log<level::ERR>("JSON file open failed");
            return -1;
        }

        // Write JSON to file
        jsonFile << jsonData.dump(2);

        jsonFile.flush();
        jsonFile.close();
        return 0;
    };

    nlohmann::ordered_json ipmiConfig = readJsonFile(IPMI_CHANNEL_CONFIG);

    for (const auto& element : ipmiConfig.items())
    {
        auto name = element.value()["name"].get<std::string>();
        if ((isActive ? name == "eth0" : name == "bond0"))
        {
            ipmiConfig[element.key()]["name"] = isActive ? "bond0" : "eth0";
            break;
        }
    }

    if (writeJsonFile(IPMI_CHANNEL_CONFIG, ipmiConfig) != 0)
    {
        log<level::ERR>("Error in write JSON data to file",
                        entry("FILE=%s", IPMI_CHANNEL_CONFIG));
        elog<InternalFailure>();
    }
}

void Bond::updateMACAddress(std::string macStr)
{
    // Write updated netdev file with new MAC using config::Parser
    config::Parser config;
    auto& netdev = config.map["NetDev"].emplace_back();
    netdev["Name"].emplace_back(eth.interfaceName());
    netdev["Kind"].emplace_back("bond");
    netdev["MACAddress"].emplace_back(macStr);
    auto& bond = config.map["Bond"].emplace_back();
    bond["Mode"].emplace_back("active-backup");
    bond["MIIMonitorSec"].emplace_back(
        std::format("{}ms", BondIntf::miiMonitor()));

    // Write to .netdev file
    auto netdevPath =
        eth.manager.get().getConfDir() / (eth.interfaceName() + ".netdev");
    config.writeFile(netdevPath);

    for (auto it = eth.manager.get().interfaces.begin();
         it != eth.manager.get().interfaces.end(); it++)
    {
        if (it->second->interfaceName() == "bond0")
        {
            it->second->addrs.clear();
        }

        if (it->second->interfaceName() != "bond0")
        {
            system::setNICUp(it->second->interfaceName(), false);
        }
    }

    system::setNICUp("bond0", false);

    sleep(2);

    execute("/bin/systemctl", "systemctl", "restart",
            "systemd-networkd.service");
}

} // namespace network
} // namespace phosphor
