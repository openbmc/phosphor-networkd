#include "config.h"

#include "inventory_mac.hpp"

#include "network_manager.hpp"
#include "types.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <stdplus/str/maps.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace phosphor::network::inventory
{

using phosphor::logging::elog;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using DbusObjectPath = std::string;
using DbusInterface = std::string;
using PropertyValue = std::string;
using DbusService = std::string;
using ObjectTree =
    stdplus::string_umap<stdplus::string_umap<std::vector<std::string>>>;

constexpr auto firstBootPath = "/var/lib/network/firstBoot_";
constexpr auto configFile = "/usr/share/network/config.json";

constexpr auto invNetworkIntf =
    "xyz.openbmc_project.Inventory.Item.NetworkInterface";
constexpr auto invRoot = "/xyz/openbmc_project/inventory";
constexpr auto mapperBus = "xyz.openbmc_project.ObjectMapper";
constexpr auto mapperObj = "/xyz/openbmc_project/object_mapper";
constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";
constexpr auto propIntf = "org.freedesktop.DBus.Properties";
constexpr auto methodGet = "Get";

Manager* manager = nullptr;
std::unique_ptr<sdbusplus::match> EthInterfaceMatch = nullptr;
std::unique_ptr<sdbusplus::match> MacAddressMatch = nullptr;
std::set<std::string> pendingInterfaces;
nlohmann::json configJson;

void stopWatchingIfComplete()
{
    if (pendingInterfaces.empty())
    {
        lg2::info("Removing the match for ethernet interfaces");
        EthInterfaceMatch = nullptr;
        MacAddressMatch = nullptr;
    }
}

void setFirstBootMACOnInterface(const std::string& intf, const std::string& mac)
{
    try
    {
        for (const auto& interface : manager->interfaces)
        {
            if (interface.first == intf)
            {
                auto returnMAC = interface.second->macAddress(mac);
                if (returnMAC == mac)
                {
                    lg2::info("Setting MAC {NET_MAC} on interface {NET_INTF}",
                              "NET_MAC", mac, "NET_INTF", intf);
                    std::error_code ec;
                    if (std::filesystem::is_directory("/var/lib/network", ec))
                    {
                        std::ofstream persistentFile(firstBootPath + intf);
                    }
                    pendingInterfaces.erase(intf);
                    break;
                }
                else
                {
                    lg2::info("MAC is Not Set on ethernet Interface");
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        lg2::warning("Unable to set inventory MAC on {NET_INTF}: {ERROR}",
                     "NET_INTF", intf, "ERROR", e.what());
    }
}

auto getFromInventory(sdbusplus::bus_t& bus, const std::string& intfName)
    -> std::optional<stdplus::EtherAddr>
{
    std::string interfaceName = configJson[intfName];

    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(invNetworkIntf);

    auto depth = 0;

    auto mapperCall =
        bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetSubTree");

    mapperCall.append(invRoot, depth, interfaces);

    auto mapperReply = [&]() {
        try
        {
            return bus.call(mapperCall);
        }
        catch (const sdbusplus::exception_t& e)
        {
            // Mapper may give an exception when there are no results.  Turn
            // it into an empty message.
            lg2::warning("Error in mapper call");
            return sdbusplus::message_t{};
        }
    }();

    if (!mapperReply)
    {
        return std::nullopt;
    }

    auto objectTree = mapperReply.unpack<ObjectTree>();

    if (objectTree.empty())
    {
        lg2::warning("No Object has implemented the interface {NET_INTF}",
                     "NET_INTF", invNetworkIntf);
        return std::nullopt;
    }

    DbusObjectPath objPath;
    DbusService service;

    // Preserve legacy configs with an empty inventory name when there is only
    // one inventory object.
    if (interfaceName.empty() && 1 == objectTree.size())
    {
        objPath = objectTree.begin()->first;
        service = objectTree.begin()->second.begin()->first;
    }
    else
    {
        // Match the configured inventory object name.
        for (const auto& object : objectTree)
        {
            lg2::info("Get info on interface {NET_INTF}, object {OBJ}",
                      "NET_INTF", interfaceName, "OBJ", object.first);
            if (object.first.ends_with("/" + interfaceName))
            {
                objPath = object.first;
                service = object.second.begin()->first;
                break;
            }
        }

        if (objPath.empty())
        {
            lg2::info("Inventory object for {NET_INTF} is not available yet",
                      "NET_INTF", interfaceName);
            return std::nullopt;
        }
    }

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      propIntf, methodGet);

    method.append(invNetworkIntf, "MACAddress");

    auto reply = [&]() {
        try
        {
            return bus.call(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            lg2::error(
                "Failed to get MACAddress for path {DBUS_PATH} interface {DBUS_INTF}",
                "DBUS_PATH", objPath, "DBUS_INTF", invNetworkIntf);
            elog<InternalFailure>();
        }
    }();

    auto value = reply.unpack<std::variant<std::string>>();

    return stdplus::fromStr<stdplus::EtherAddr>(std::get<std::string>(value));
}

bool setInventoryMACOnSystem(sdbusplus::bus_t& bus, const std::string& intfname)
{
    try
    {
        auto inventoryMAC = getFromInventory(bus, intfname);
        if (!inventoryMAC)
        {
            lg2::info("Nothing is present in Inventory");
            return false;
        }

        auto macStr = stdplus::toStr(*inventoryMAC);
        lg2::info("Mac Address {NET_MAC} in Inventory on Interface {NET_INTF}",
                  "NET_MAC", macStr, "NET_INTF", intfname);
        setFirstBootMACOnInterface(intfname, macStr);
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception occurred during getting of MAC "
                   "address from Inventory");
        return false;
    }
    return true;
}

// register the matches to be monitored from inventory manager
void registerSignals(sdbusplus::bus_t& bus)
{
    lg2::info("Registering the Inventory Signals Matcher");

    auto callback = [&](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::object_path objPath;
        m.read(objPath, interfacesProperties);

        for (const auto& pattern : configJson.items())
        {
            if (pendingInterfaces.contains(pattern.key()) &&
                objPath.string().ends_with(
                    "/" + pattern.value().get<std::string>()))
            {
                for (auto& interface : interfacesProperties)
                {
                    if (interface.first == invNetworkIntf)
                    {
                        for (const auto& property : interface.second)
                        {
                            if (property.first == "MACAddress")
                            {
                                // Only set mac address on interface once the
                                // firstboot file does not exist or it is being
                                // FORCE_SYNC_MAC_FROM_INVENTORY
                                if (FORCE_SYNC_MAC_FROM_INVENTORY ||
                                    !std::filesystem::exists(
                                        firstBootPath + pattern.key()))
                                {
                                    setFirstBootMACOnInterface(
                                        pattern.key(),
                                        std::get<std::string>(property.second));
                                }
                                else
                                {
                                    lg2::info(
                                        "First-boot marker exists for {NET_INTF}, skipping inventory MAC sync",
                                        "NET_INTF", pattern.key());
                                    // No synchronization is needed anymore.
                                    pendingInterfaces.erase(pattern.key());
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
        stopWatchingIfComplete();
    };

    MacAddressMatch = std::make_unique<sdbusplus::match>(
        bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/"
        "inventory'",
        callback);
}

void watchEthernetInterface(sdbusplus::bus_t& bus)
{
    auto handle_interface = [&](auto infname) {
        if (configJson.find(infname) == configJson.end())
        {
            // ethernet interface not found in configJSON
            // check if it is not sit0 interface, as it is
            // expected.
            if (infname != "sit0")
            {
                lg2::error("Wrong Interface Name in Config Json");
            }
        }
        else if (pendingInterfaces.contains(infname))
        {
            setInventoryMACOnSystem(bus, infname);
            stopWatchingIfComplete();
        }
    };

    auto mycallback = [&, handle_interface](sdbusplus::message_t& m) {
        std::map<DbusObjectPath,
                 std::map<DbusInterface, std::variant<PropertyValue>>>
            interfacesProperties;

        sdbusplus::object_path objPath;
        std::pair<std::string, std::string> ethPair;
        m.read(objPath, interfacesProperties);

        for (const auto& interfaces : interfacesProperties)
        {
            lg2::info("Check {DBUS_INTF} for sdbus response", "DBUS_INTF",
                      interfaces.first);
            if (interfaces.first ==
                "xyz.openbmc_project.Network.EthernetInterface")
            {
                for (const auto& property : interfaces.second)
                {
                    if (property.first == "InterfaceName")
                    {
                        handle_interface(
                            std::get<std::string>(property.second));

                        break;
                    }
                }
                break;
            }
        }
    };

    // Determine all pending interfaces before attempting any synchronization.
    for (const auto& interfaceString : configJson.items())
    {
        if (FORCE_SYNC_MAC_FROM_INVENTORY ||
            !std::filesystem::exists(firstBootPath + interfaceString.key()))
        {
            lg2::info("Check VPD for MAC: {REASON}", "REASON",
                      (FORCE_SYNC_MAC_FROM_INVENTORY)
                          ? "Force sync enabled"
                          : "First boot file is not present");
            pendingInterfaces.insert(interfaceString.key());
        }
        else
        {
            lg2::info(
                "First-boot marker exists for {NET_INTF}, skipping inventory MAC sync",
                "NET_INTF", interfaceString.key());
        }
    }

    if (pendingInterfaces.empty())
    {
        return;
    }

    registerSignals(bus);
    EthInterfaceMatch = std::make_unique<sdbusplus::match>(
        bus,
        "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
        "member='InterfacesAdded',path='/xyz/openbmc_project/network'",
        mycallback);

    // The VPD may already have been assigned because phosphor-inventory-manager
    // started ahead of the network service. Read the VPD directly and assign
    // the MAC address despite this possibility.

    for (const auto& interfaceString : configJson.items())
    {
        for (const auto& intf : manager->interfaces)
        {
            if (intf.first == interfaceString.key())
            {
                handle_interface(intf.first);
            }
        }
    }
}

std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                               stdplus::PinnedRef<Manager> m)
{
    manager = &m.get();
    std::ifstream in(configFile);
    in >> configJson;
    watchEthernetInterface(bus);
    return nullptr;
}

} // namespace phosphor::network::inventory
