#include "config.h"

#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "types.hpp"
#ifdef SYNC_MAC_FROM_INVENTORY
#include "util.hpp"
#endif

#include <fmt/format.h>
#include <linux/netlink.h>

#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#ifdef SYNC_MAC_FROM_INVENTORY
#include <nlohmann/json.hpp>
#endif
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/signal.hpp>
#include <stdplus/signal.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using DbusObjectPath = std::string;
using DbusInterface = std::string;
using PropertyValue = std::string;

constexpr char NETWORK_CONF_DIR[] = "/etc/systemd/network";

constexpr char DEFAULT_OBJPATH[] = "/xyz/openbmc_project/network";

constexpr auto firstBootPath = "/var/lib/network/firstBoot_";
constexpr auto configFile = "/usr/share/network/config.json";

constexpr auto invNetworkIntf =
    "xyz.openbmc_project.Inventory.Item.NetworkInterface";

namespace phosphor
{
namespace network
{

std::unique_ptr<Manager> manager = nullptr;
std::unique_ptr<Timer> refreshObjectTimer = nullptr;
std::unique_ptr<Timer> reloadTimer = nullptr;

#ifdef SYNC_MAC_FROM_INVENTORY
std::unique_ptr<sdbusplus::bus::match_t> EthInterfaceMatch = nullptr;
std::vector<std::string> first_boot_status;

bool setInventoryMACOnSystem(sdbusplus::bus_t& bus,
                             const nlohmann::json& configJson,
                             const std::string& intfname)
{
    try
    {
        auto inventoryMAC = mac_address::getfromInventory(bus, intfname);
        if (inventoryMAC != ether_addr{})
        {
            auto macStr = std::to_string(inventoryMAC);
            log<level::INFO>("Mac Address in Inventory on ",
                             entry("Interface : ", intfname.c_str()),
                             entry("MAC Address :", macStr.c_str()));
            manager->setFistBootMACOnInterface(
                std::make_pair(intfname.c_str(), std::move(macStr)));
            first_boot_status.push_back(intfname.c_str());
            bool status = true;
            for (const auto& keys : configJson.items())
            {
                if (!(std::find(first_boot_status.begin(),
                                first_boot_status.end(),
                                keys.key()) != first_boot_status.end()))
                {
                    log<level::INFO>("Interface MAC is NOT set from VPD"),
                        entry("INTERFACE", keys.key().c_str());
                    status = false;
                }
            }
            if (status)
            {
                log<level::INFO>("Removing the match for ethernet interfaces");
                EthInterfaceMatch = nullptr;
            }
        }
        else
        {
            log<level::INFO>("Nothing is present in Inventory");
            return false;
        }
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Exception occurred during getting of MAC "
                        "address from Inventory");
        return false;
    }
    return true;
}

// register the macthes to be monitored from inventory manager
void registerSignals(sdbusplus::bus_t& bus, const nlohmann::json& configJson)
{
    log<level::INFO>("Registering the Inventory Signals Matcher");

    static std::unique_ptr<sdbusplus::bus::match_t> MacAddressMatch;

    auto callback = [&](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::message::object_path objPath;
        std::pair<std::string, std::string> ethPair;
        m.read(objPath, interfacesProperties);

        for (const auto& pattern : configJson.items())
        {
            if (objPath.str.find(pattern.value()) != std::string::npos)
            {
                for (auto& interface : interfacesProperties)
                {
                    if (interface.first == invNetworkIntf)
                    {
                        for (const auto& property : interface.second)
                        {
                            if (property.first == "MACAddress")
                            {
                                ethPair = std::make_pair(
                                    pattern.key(),
                                    std::get<std::string>(property.second));
                                break;
                            }
                        }
                        break;
                    }
                }
                if (!(ethPair.first.empty() || ethPair.second.empty()))
                {
                    manager->setFistBootMACOnInterface(ethPair);
                }
            }
        }
    };

    MacAddressMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/"
        "inventory'",
        callback);
}

void watchEthernetInterface(sdbusplus::bus_t& bus,
                            const nlohmann::json& configJson)
{
    auto mycallback = [&](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::message::object_path objPath;
        std::pair<std::string, std::string> ethPair;
        m.read(objPath, interfacesProperties);
        for (const auto& interfaces : interfacesProperties)
        {
            if (interfaces.first ==
                "xyz.openbmc_project.Network.EthernetInterface")
            {
                for (const auto& property : interfaces.second)
                {
                    if (property.first == "InterfaceName")
                    {
                        std::string infname =
                            std::get<std::string>(property.second);

                        if (configJson.find(infname) == configJson.end())
                        {
                            // ethernet interface not found in configJSON
                            // check if it is not sit0 interface, as it is
                            // expected.
                            if (infname != "sit0")
                            {
                                log<level::ERR>(
                                    "Wrong Interface Name in Config Json");
                            }
                        }
                        else
                        {
                            if (!setInventoryMACOnSystem(bus, configJson,
                                                         infname))
                            {
                                registerSignals(bus, configJson);
                                EthInterfaceMatch = nullptr;
                            }
                        }
                        break;
                    }
                }
                break;
            }
        }
    };
    // Incase if phosphor-inventory-manager started early and the VPD is already
    // collected by the time network service has come up, better to check the
    // VPD directly and set the MAC Address on the respective Interface.

    bool registeredSignals = false;
    for (const auto& interfaceString : configJson.items())
    {
        if (!std::filesystem::exists(firstBootPath + interfaceString.key()) &&
            !registeredSignals)
        {

            log<level::INFO>(
                "First boot file is not present, check VPD for MAC");
            EthInterfaceMatch = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
                "member='InterfacesAdded',path='/xyz/openbmc_project/network'",
                mycallback);
            registeredSignals = true;
        }
    }
}

#endif

/** @brief refresh the network objects. */
void refreshObjects()
{
    if (manager)
    {
        log<level::INFO>("Refreshing the objects.");
        manager->createChildObjects();
        log<level::INFO>("Refreshing complete.");
    }
}

void reloadNetworkd()
{
    if (manager)
    {
        log<level::INFO>("Sending networkd reload");
        manager->doReloadConfigs();
        log<level::INFO>("Done networkd reload");
    }
}

void initializeTimers(sdeventplus::Event& event)
{
    refreshObjectTimer =
        std::make_unique<Timer>(event, std::bind(refreshObjects));
    reloadTimer = std::make_unique<Timer>(event, std::bind(reloadNetworkd));
}

void termCb(sdeventplus::source::Signal& signal, const struct signalfd_siginfo*)
{
    log<level::NOTICE>("Got TERM, exiting");
    signal.get_event().exit(0);
}

int main()
{
    auto event = sdeventplus::Event::get_default();
    stdplus::signal::block(SIGTERM);
    sdeventplus::source::Signal(event, SIGTERM, termCb).set_floating(true);

    initializeTimers(event);

    auto bus = sdbusplus::bus::new_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Add sdbusplus Object Manager for the 'root' path of the network manager.
    sdbusplus::server::manager_t objManager(bus, DEFAULT_OBJPATH);
    bus.request_name(DEFAULT_BUSNAME);

    manager = std::make_unique<Manager>(bus, DEFAULT_OBJPATH, NETWORK_CONF_DIR);

    // RTNETLINK event handler
    netlink::Server svr(event);

#ifdef SYNC_MAC_FROM_INVENTORY
    std::ifstream in(configFile);
    nlohmann::json configJson;
    in >> configJson;
    watchEthernetInterface(bus, configJson);
#endif

    // Trigger the initial object scan
    // This is intentionally deferred, to ensure that systemd-networkd is
    // fully configured.
    refreshObjectTimer->restartOnce(refreshTimeout);

    return event.loop();
}

} // namespace network
} // namespace phosphor

int main(int /*argc*/, char** /*argv*/)
{
    try
    {
        return phosphor::network::main();
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("FAILED: {}", e.what());
        log<level::ERR>(msg.c_str(), entry("ERROR", e.what()));
        return 1;
    }
}
