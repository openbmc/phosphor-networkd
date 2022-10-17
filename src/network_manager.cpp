#include "config.h"

#include "network_manager.hpp"

#include "ipaddress.hpp"
#include "network_config.hpp"
#include "system_queries.hpp"
#include "types.hpp"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

constexpr char SYSTEMD_BUSNAME[] = "org.freedesktop.systemd1";
constexpr char SYSTEMD_PATH[] = "/org/freedesktop/systemd1";
constexpr char SYSTEMD_INTERFACE[] = "org.freedesktop.systemd1.Manager";
constexpr auto FirstBootFile = "/var/lib/network/firstBoot_";

constexpr char NETWORKD_BUSNAME[] = "org.freedesktop.network1";
constexpr char NETWORKD_PATH[] = "/org/freedesktop/network1";
constexpr char NETWORKD_INTERFACE[] = "org.freedesktop.network1.Manager";

namespace phosphor
{
namespace network
{

extern std::unique_ptr<Timer> refreshObjectTimer;
extern std::unique_ptr<Timer> reloadTimer;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

Manager::Manager(sdbusplus::bus_t& bus, const char* objPath,
                 const fs::path& confDir) :
    details::VLANCreateIface(bus, objPath,
                             details::VLANCreateIface::action::defer_emit),
    bus(bus), objectPath(objPath)
{
    setConfDir(confDir);
}

bool Manager::createDefaultNetworkFiles()
{
    auto isCreated = false;
    try
    {
        auto interfaceStrList = system::getInterfaces();
        for (const auto& interface : interfaceStrList)
        {
            // if the interface has '.' in the name, it means that this is a
            // VLAN - don't create the network file.
            if (interface.find(".") != std::string::npos)
            {
                continue;
            }

            fs::path filePath = config::pathForIntfConf(confDir, interface);

            // create the interface specific network file
            // if not existing.
            if (!fs::is_regular_file(filePath))
            {
                bmc::writeDHCPDefault(filePath, interface);
                log<level::INFO>("Created the default network file.",
                                 entry("INTERFACE=%s", interface.c_str()));
                isCreated = true;
            }
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Unable to create the default network file");
    }

    return isCreated;
}

void Manager::setConfDir(const fs::path& dir)
{
    confDir = dir;

    if (!fs::exists(confDir))
    {
        if (!fs::create_directories(confDir))
        {
            log<level::ERR>("Unable to create the network conf dir",
                            entry("DIR=%s", confDir.c_str()));
            elog<InternalFailure>();
        }
    }
}

void Manager::createInterfaces()
{
    // clear all the interfaces first
    interfaces.clear();
    auto interfaceStrList = system::getInterfaces();
    for (auto& interface : interfaceStrList)
    {
        auto index = interface.find(".");

        // interface can be of vlan type or normal ethernet interface.
        // vlan interface looks like "interface.vlanid",so here by looking
        // at the interface name we decide that we need
        // to create the vlaninterface or normal physical interface.
        if (index != std::string::npos)
        {
            // it is vlan interface
            auto sv = std::string_view(interface);
            auto interfaceName = sv.substr(0, index);
            auto vlanStr = sv.substr(index + 1);
            uint16_t vlanId;
            auto res = std::from_chars(vlanStr.begin(), vlanStr.end(), vlanId);
            if (res.ec != std::errc() || res.ptr != vlanStr.end())
            {
                auto msg = fmt::format("Invalid VLAN: {}", vlanStr);
                log<level::ERR>(msg.c_str());
                continue;
            }
            auto it = interfaces.find(interfaceName);
            if (it == interfaces.end())
            {
                auto msg = fmt::format("Missing interface({}) for VLAN({}): {}",
                                       interfaceName, vlanId, interface);
                log<level::ERR>(msg.c_str());
                continue;
            }
            it->second->loadVLAN(objectPath, vlanId);
            continue;
        }
        // normal ethernet interface
        config::Parser config(config::pathForIntfConf(confDir, interface));

        auto intf = std::make_unique<phosphor::network::EthernetInterface>(
            bus, *this, getInterfaceInfo(interface), objectPath, config);

        intf->createIPAddressObjects();
        intf->createStaticNeighborObjects();
        intf->loadNameServers(config);

        this->interfaces.emplace(std::move(interface), std::move(intf));
    }
}

void Manager::createChildObjects()
{
    routeTable.refresh();

    // creates the ethernet interface dbus object.
    createInterfaces();

    systemConf.reset(nullptr);
    dhcpConf.reset(nullptr);

    fs::path objPath = objectPath;
    objPath /= "config";

    // create the system conf object.
    systemConf = std::make_unique<phosphor::network::SystemConfiguration>(
        bus, objPath.string());
    // create the dhcp conf object.
    objPath /= "dhcp";
    dhcpConf = std::make_unique<phosphor::network::dhcp::Configuration>(
        bus, objPath.string(), *this);
}

ObjectPath Manager::vlan(std::string interfaceName, uint32_t id)
{
    if (id == 0 || id >= 4095)
    {
        log<level::ERR>("VLAN ID is not valid", entry("VLANID=%u", id));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("VLANId"),
            Argument::ARGUMENT_VALUE(std::to_string(id).c_str()));
    }

    auto it = interfaces.find(interfaceName);
    if (it == interfaces.end())
    {
        using ResourceErr =
            phosphor::logging::xyz::openbmc_project::Common::ResourceNotFound;
        elog<ResourceNotFound>(ResourceErr::RESOURCE(interfaceName.c_str()));
    }
    return it->second->createVLAN(id);
}

void Manager::reset()
{
    if (fs::is_directory(confDir))
    {
        for (const auto& file : fs::directory_iterator(confDir))
        {
            fs::remove(file.path());
        }
    }
    createDefaultNetworkFiles();
    log<level::INFO>("Network Factory Reset queued.");
}

// Need to merge the below function with the code which writes the
// config file during factory reset.
// TODO openbmc/openbmc#1751
void Manager::writeToConfigurationFile()
{
    // write all the static ip address in the systemd-network conf file
    for (const auto& intf : interfaces)
    {
        intf.second->writeConfigurationFile();
    }
}

#ifdef SYNC_MAC_FROM_INVENTORY
void Manager::setFistBootMACOnInterface(
    const std::pair<std::string, std::string>& inventoryEthPair)
{
    for (const auto& interface : interfaces)
    {
        if (interface.first == inventoryEthPair.first)
        {
            auto returnMAC =
                interface.second->macAddress(inventoryEthPair.second);
            if (returnMAC == inventoryEthPair.second)
            {
                log<level::INFO>("Set the MAC on "),
                    entry("interface : ", interface.first.c_str()),
                    entry("MAC : ", inventoryEthPair.second.c_str());
                std::error_code ec;
                if (std::filesystem::is_directory("/var/lib/network", ec))
                {
                    std::ofstream persistentFile(FirstBootFile +
                                                 interface.first);
                }
                break;
            }
            else
            {
                log<level::INFO>("MAC is Not Set on ethernet Interface");
            }
        }
    }
}

#endif

void Manager::reloadConfigs()
{
    reloadTimer->restartOnce(reloadTimeout);
    // Ensure that the next refresh happens after reconfiguration
    refreshObjectTimer->setRemaining(reloadTimeout + refreshTimeout);
}

void Manager::doReloadConfigs()
{
    for (auto& hook : reloadPreHooks)
    {
        try
        {
            hook();
        }
        catch (const std::exception& ex)
        {
            log<level::ERR>("Failed executing reload hook, ignoring",
                            entry("ERR=%s", ex.what()));
        }
    }
    reloadPreHooks.clear();
    try
    {
        auto method = bus.new_method_call(NETWORKD_BUSNAME, NETWORKD_PATH,
                                          NETWORKD_INTERFACE, "Reload");
        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception_t& ex)
    {
        log<level::ERR>("Failed to reload configuration",
                        entry("ERR=%s", ex.what()));
        elog<InternalFailure>();
    }
    // Ensure reconfiguration has enough time
    refreshObjectTimer->setRemaining(refreshTimeout);
}

} // namespace network
} // namespace phosphor
