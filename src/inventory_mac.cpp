#include "config.h"

#include "inventory_mac.hpp"

#include "network_manager.hpp"
#include "types.hpp"

#include <filesystem>
#include <fstream>
#include <memory>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <string>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::network::inventory
{

using phosphor::logging::elog;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;
using sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using DbusObjectPath = std::string;
using DbusInterface = std::string;
using PropertyValue = std::string;
using DbusService = std::string;
using ObjectTree = string_umap<string_umap<std::vector<std::string>>>;

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
std::unique_ptr<sdbusplus::bus::match_t> EthInterfaceMatch = nullptr;
std::vector<std::string> first_boot_status;

void setFirstBootMACOnInterface(const std::string& intf, const std::string& mac)
{
    for (const auto& interface : manager->interfaces)
    {
        if (interface.first == intf)
        {
            auto returnMAC = interface.second->macAddress(mac);
            if (returnMAC == mac)
            {
                log<level::INFO>(fmt::format("Setting MAC on {}", intf).c_str(),
                                 entry("INTF=%s", intf.c_str()),
                                 entry("MAC=%s", mac.c_str()));
                std::error_code ec;
                if (std::filesystem::is_directory("/var/lib/network", ec))
                {
                    std::ofstream persistentFile(firstBootPath + intf);
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

ether_addr getfromInventory(sdbusplus::bus_t& bus, const std::string& intfName)
{
    std::string interfaceName = intfName;

    // load the config JSON from the Read Only Path
    std::ifstream in(configFile);
    nlohmann::json configJson;
    in >> configJson;
    interfaceName = configJson[intfName];

    std::vector<DbusInterface> interfaces;
    interfaces.emplace_back(invNetworkIntf);

    auto depth = 0;

    auto mapperCall =
        bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetSubTree");

    mapperCall.append(invRoot, depth, interfaces);

    auto mapperReply = bus.call(mapperCall);
    if (mapperReply.is_method_error())
    {
        log<level::ERR>("Error in mapper call");
        elog<InternalFailure>();
    }

    ObjectTree objectTree;
    mapperReply.read(objectTree);

    if (objectTree.empty())
    {
        log<level::ERR>("No Object has implemented the interface",
                        entry("INTERFACE=%s", invNetworkIntf));
        elog<InternalFailure>();
    }

    DbusObjectPath objPath;
    DbusService service;

    if (1 == objectTree.size())
    {
        objPath = objectTree.begin()->first;
        service = objectTree.begin()->second.begin()->first;
    }
    else
    {
        // If there are more than 2 objects, object path must contain the
        // interface name
        for (auto const& object : objectTree)
        {
            log<level::INFO>("interface",
                             entry("INT=%s", interfaceName.c_str()));
            log<level::INFO>("object", entry("OBJ=%s", object.first.c_str()));

            if (std::string::npos != object.first.find(interfaceName.c_str()))
            {
                objPath = object.first;
                service = object.second.begin()->first;
                break;
            }
        }

        if (objPath.empty())
        {
            log<level::ERR>("Can't find the object for the interface",
                            entry("intfName=%s", interfaceName.c_str()));
            elog<InternalFailure>();
        }
    }

    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      propIntf, methodGet);

    method.append(invNetworkIntf, "MACAddress");

    auto reply = bus.call(method);
    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to get MACAddress",
                        entry("PATH=%s", objPath.c_str()),
                        entry("INTERFACE=%s", invNetworkIntf));
        elog<InternalFailure>();
    }

    std::variant<std::string> value;
    reply.read(value);
    return ToAddr<ether_addr>{}(std::get<std::string>(value));
}

bool setInventoryMACOnSystem(sdbusplus::bus_t& bus,
                             const nlohmann::json& configJson,
                             const std::string& intfname)
{
    try
    {
        auto inventoryMAC = getfromInventory(bus, intfname);
        if (inventoryMAC != ether_addr{})
        {
            auto macStr = std::to_string(inventoryMAC);
            log<level::INFO>("Mac Address in Inventory on ",
                             entry("Interface : ", intfname.c_str()),
                             entry("MAC Address :", macStr.c_str()));
            setFirstBootMACOnInterface(intfname, macStr);
            first_boot_status.push_back(intfname);
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
                                setFirstBootMACOnInterface(
                                    pattern.key(),
                                    std::get<std::string>(property.second));
                                break;
                            }
                        }
                        break;
                    }
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
        if ((FORCE_SYNC_MAC_FROM_INVENTORY ||
             !std::filesystem::exists(firstBootPath + interfaceString.key())) &&
            !registeredSignals)
        {
            auto msg = fmt::format("{}, check VPD for MAC",
                                   (FORCE_SYNC_MAC_FROM_INVENTORY)
                                       ? "Force sync enabled"
                                       : "First boot file is not present");
            log<level::INFO>(msg.c_str());
            EthInterfaceMatch = std::make_unique<sdbusplus::bus::match_t>(
                bus,
                "interface='org.freedesktop.DBus.ObjectManager',type='signal',"
                "member='InterfacesAdded',path='/xyz/openbmc_project/network'",
                mycallback);
            registeredSignals = true;
        }
    }
}

std::unique_ptr<Runtime> watch(sdbusplus::bus_t& bus, Manager& m)
{
    manager = &m;
    std::ifstream in(configFile);
    nlohmann::json configJson;
    in >> configJson;
    watchEthernetInterface(bus, configJson);
    return nullptr;
}

} // namespace phosphor::network::inventory
