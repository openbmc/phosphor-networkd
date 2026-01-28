#include "hostname_manager.hpp"

#include "network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <stdplus/pinned.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

static constexpr const char* mapperBusName = "xyz.openbmc_project.ObjectMapper";
static constexpr const char* mapperObjPath =
    "/xyz/openbmc_project/object_mapper";
static constexpr const char* mapperIntf = "xyz.openbmc_project.ObjectMapper";
static constexpr const char* inventoryRoot = "/xyz/openbmc_project/inventory";
static constexpr const char* bmcItemIntf =
    "xyz.openbmc_project.Inventory.Item.Bmc";
static constexpr const char* assetIntf =
    "xyz.openbmc_project.Inventory.Decorator.Asset";
static constexpr const char* networkItemIntf =
    "xyz.openbmc_project.Inventory.Item.NetworkInterface";
static constexpr const char* propIntf = "org.freedesktop.DBus.Properties";
static constexpr const char* hostnamedBusName = "org.freedesktop.hostname1";
static constexpr const char* hostnamedObjPath = "/org/freedesktop/hostname1";
static constexpr const char* hostnamedIntf = "org.freedesktop.hostname1";

HostnameManager::HostnameManager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                                 stdplus::PinnedRef<Manager> manager) :
    bus(bus), manager(manager)
{}

void HostnameManager::initialize()
{
    if (!isFirstBoot())
    {
        lg2::info("Hostname already set on previous boot, skipping");
        return;
    }

    lg2::info("First boot detected, setting unique hostname");
    setUniqueHostname();
    markHostnameSet();
}

bool HostnameManager::isFirstBoot() const
{
    return !std::filesystem::exists(firstBootFile);
}

void HostnameManager::markHostnameSet()
{
    try
    {
        // Create parent directories if they don't exist
        std::filesystem::path firstBootFilePath(firstBootFile);
        std::filesystem::create_directories(firstBootFilePath.parent_path());

        std::ofstream file(firstBootFile);
        if (!file)
        {
            lg2::error("Failed to create firstBoot file: {PATH}", "PATH",
                       firstBootFile);
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception creating firstBoot file: {ERROR}", "ERROR", e);
    }
}

std::string HostnameManager::getBmcSerialNumber()
{
    try
    {
        // Get BMC item path from inventory
        auto method = bus.get().new_method_call(mapperBusName, mapperObjPath,
                                                mapperIntf, "GetSubTree");
        method.append(inventoryRoot, 0, std::vector<std::string>{bmcItemIntf});

        auto reply = bus.get().call(method);

        std::map<std::string, std::map<std::string, std::vector<std::string>>>
            response;
        reply.read(response);

        if (response.empty())
        {
            lg2::warning("No BMC item found in inventory");
            return "";
        }

        // Get the first BMC item path
        const auto& bmcPath = response.begin()->first;
        const auto& serviceMap = response.begin()->second;

        if (serviceMap.empty())
        {
            lg2::warning("No service found for BMC item");
            return "";
        }

        const auto& serviceName = serviceMap.begin()->first;

        // Get SerialNumber property
        auto propMethod = bus.get().new_method_call(
            serviceName.c_str(), bmcPath.c_str(), propIntf, "Get");
        propMethod.append(assetIntf, "SerialNumber");

        auto propReply = bus.get().call(propMethod);
        std::variant<std::string> serialNumber;
        propReply.read(serialNumber);

        std::string sn = std::get<std::string>(serialNumber);
        if (sn.empty())
        {
            lg2::warning("BMC Serial Number is empty");
        }
        else
        {
            lg2::info("Retrieved BMC Serial Number: {SN}", "SN", sn);
        }

        return sn;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to get BMC serial number: {ERROR}", "ERROR", e);
        return "";
    }
}

std::string HostnameManager::getMacAddress()
{
    try
    {
        auto method = bus.get().new_method_call(mapperBusName, mapperObjPath,
                                                mapperIntf, "GetSubTree");
        method.append(inventoryRoot, 0,
                      std::vector<std::string>{networkItemIntf});

        auto reply = bus.get().call(method);

        std::map<std::string, std::map<std::string, std::vector<std::string>>>
            response;
        reply.read(response);

        if (response.empty())
        {
            lg2::warning("No network interface found in inventory");
            return "";
        }

        // Get the first network interface path
        const auto& netPath = response.begin()->first;
        const auto& serviceMap = response.begin()->second;

        if (serviceMap.empty())
        {
            lg2::warning("No service found for network interface");
            return "";
        }

        const auto& serviceName = serviceMap.begin()->first;

        // Get MACAddress property
        auto propMethod = bus.get().new_method_call(
            serviceName.c_str(), netPath.c_str(), propIntf, "Get");
        propMethod.append(networkItemIntf, "MACAddress");

        auto propReply = bus.get().call(propMethod);
        std::variant<std::string> macAddress;
        propReply.read(macAddress);

        std::string mac = std::get<std::string>(macAddress);
        if (mac.empty())
        {
            lg2::warning("MAC Address is empty");
        }
        else
        {
            lg2::info("Retrieved MAC Address: {MAC}", "MAC", mac);
        }

        return mac;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to get MAC address: {ERROR}", "ERROR", e);
        return "";
    }
}

std::string HostnameManager::getCurrentHostname()
{
    try
    {
        auto method = bus.get().new_method_call(
            hostnamedBusName, hostnamedObjPath, propIntf, "Get");
        method.append(hostnamedIntf, "Hostname");

        auto reply = bus.get().call(method);
        std::variant<std::string> hostname;
        reply.read(hostname);

        return std::get<std::string>(hostname);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to get current hostname: {ERROR}", "ERROR", e);
        return "localhost";
    }
}

bool HostnameManager::setHostname(const std::string& hostname)
{
    try
    {
        auto method =
            bus.get().new_method_call(hostnamedBusName, hostnamedObjPath,
                                      hostnamedIntf, "SetStaticHostname");
        method.append(hostname, false);

        bus.get().call(method);
        lg2::info("Successfully set hostname to: {HOSTNAME}", "HOSTNAME",
                  hostname);
        return true;
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to set hostname to {HOSTNAME}: {ERROR}", "HOSTNAME",
                   hostname, "ERROR", e);
        return false;
    }
}

void HostnameManager::setUniqueHostname()
{
    std::string currentHostname = getCurrentHostname();
    std::string uniqueSuffix;

    // Try to get BMC serial number first
    std::string serialNumber = getBmcSerialNumber();
    if (!serialNumber.empty())
    {
        uniqueSuffix = serialNumber;
        lg2::info("Using BMC Serial Number for unique hostname");
    }
    else
    {
        // Fallback to MAC address
        lg2::warning(
            "BMC Serial Number not available, falling back to MAC address");
        std::string macAddress = getMacAddress();
        if (!macAddress.empty())
        {
            uniqueSuffix = macAddress;
            lg2::info("Using MAC Address for unique hostname");
        }
        else
        {
            lg2::error(
                "Neither Serial Number nor MAC Address available, cannot set unique hostname");
            return;
        }
    }

    // Construct and set unique hostname
    std::string newHostname = currentHostname + "-" + uniqueSuffix;

    if (setHostname(newHostname))
    {
        lg2::info("Unique hostname set successfully: {HOSTNAME}", "HOSTNAME",
                  newHostname);
    }
    else
    {
        lg2::error("Failed to set unique hostname");
    }
}

} // namespace network
} // namespace phosphor

