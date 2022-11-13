#include "config.h"

#include "network_manager.hpp"

#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "system_queries.hpp"
#include "types.hpp"

#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/message.hpp>
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

static constexpr const char enabledMatch[] =
    "type='signal',sender='org.freedesktop.network1',path_namespace='/org/"
    "freedesktop/network1/"
    "link',interface='org.freedesktop.DBus.Properties',member='"
    "PropertiesChanged',arg0='org.freedesktop.network1.Link',";

Manager::Manager(sdbusplus::bus_t& bus, const char* objPath,
                 const fs::path& confDir) :
    details::VLANCreateIface(bus, objPath,
                             details::VLANCreateIface::action::defer_emit),
    bus(bus), objectPath(objPath),
    systemdNetworkdEnabledMatch(
        bus, enabledMatch, [&](sdbusplus::message_t& m) {
            std::string intf;
            std::unordered_map<std::string, std::variant<std::string>> values;
            try
            {
                m.read(intf, values);
                auto it = values.find("AdministrativeState");
                if (it == values.end())
                {
                    return;
                }
                const std::string_view obj = m.get_path();
                auto sep = obj.rfind('/');
                if (sep == obj.npos || sep + 3 > obj.size())
                {
                    throw std::invalid_argument("Invalid obj path");
                }
                auto ifidx = DecodeInt<unsigned, 10>{}(obj.substr(sep + 3));
                const auto& state = std::get<std::string>(it->second);
                handleAdminState(state, ifidx);
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(
                    fmt::format("AdministrativeState match parsing failed: {}",
                                e.what())
                        .c_str(),
                    entry("ERROR=%s", e.what()));
            }
        })
{
    setConfDir(confDir);
    std::vector<
        std::tuple<int32_t, std::string, sdbusplus::message::object_path>>
        links;
    try
    {
        auto rsp =
            bus.new_method_call("org.freedesktop.network1",
                                "/org/freedesktop/network1",
                                "org.freedesktop.network1.Manager", "ListLinks")
                .call();
        rsp.read(links);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        // Any failures are systemd-network not being ready
    }
    for (const auto& link : links)
    {
        unsigned ifidx = std::get<0>(link);
        auto obj = fmt::format("/org/freedesktop/network1/link/_3{}", ifidx);
        auto req =
            bus.new_method_call("org.freedesktop.network1", obj.c_str(),
                                "org.freedesktop.DBus.Properties", "Get");
        req.append("org.freedesktop.network1.Link", "AdministrativeState");
        auto rsp = req.call();
        std::variant<std::string> val;
        rsp.read(val);
        handleAdminState(std::get<std::string>(val), ifidx);
    }
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

void Manager::createInterface(const InterfaceInfo& info, bool enabled)
{
    removeInterface(info);
    config::Parser config(config::pathForIntfConf(confDir, *info.name));
    auto intf = std::make_unique<EthernetInterface>(
        bus, *this, info, objectPath, config, true, enabled);
    intf->createIPAddressObjects();
    intf->createStaticNeighborObjects();
    intf->loadNameServers(config);
    intf->loadNTPServers(config);
    auto ptr = intf.get();
    interfaces.emplace(*info.name, std::move(intf));
    interfacesByIdx.emplace(info.idx, ptr);
}

void Manager::addInterface(const InterfaceInfo& info)
{
    auto it = systemdNetworkdEnabled.find(info.idx);
    if (it != systemdNetworkdEnabled.end())
    {
        createInterface(info, it->second);
    }
    else
    {
        undiscoveredIntfInfo.insert_or_assign(info.idx, std::move(info));
    }
}

void Manager::removeInterface(const InterfaceInfo& info)
{
    auto iit = interfacesByIdx.find(info.idx);
    auto nit = interfaces.end();
    if (info.name)
    {
        nit = interfaces.find(*info.name);
        if (nit != interfaces.end() && iit != interfacesByIdx.end() &&
            nit->second.get() != iit->second)
        {
            fmt::print(stderr, "Removed interface desync detected\n");
            fflush(stderr);
            std::abort();
        }
    }
    else if (iit != interfacesByIdx.end())
    {
        for (nit = interfaces.begin(); nit != interfaces.end(); ++nit)
        {
            if (nit->second.get() == iit->second)
            {
                break;
            }
        }
    }

    if (iit != interfacesByIdx.end())
    {
        interfacesByIdx.erase(iit);
    }
    else
    {
        undiscoveredIntfInfo.erase(info.idx);
    }
    if (nit != interfaces.end())
    {
        interfaces.erase(nit);
    }
}

inline void getIntfOrLog(const decltype(Manager::interfacesByIdx)& intfs,
                         unsigned idx, auto&& cb)
{
    auto it = intfs.find(idx);
    if (it == intfs.end())
    {
        auto msg = fmt::format("Interface `{}` not found", idx);
        log<level::ERR>(msg.c_str(), entry("IFIDX=%u", idx));
        return;
    }
    cb(*it->second);
}

void Manager::addAddress(const AddressInfo& info)
{
    getIntfOrLog(interfacesByIdx, info.ifidx,
                 [&](auto& intf) { intf.addAddr(info); });
}

void Manager::removeAddress(const AddressInfo& info)
{
    getIntfOrLog(interfacesByIdx, info.ifidx,
                 [&](auto& intf) { intf.addrs.erase(info.ifaddr); });
}

void Manager::addNeighbor(const NeighborInfo& info)
{
    getIntfOrLog(interfacesByIdx, info.ifidx,
                 [&](auto& intf) { intf.addStaticNeigh(info); });
}

void Manager::removeNeighbor(const NeighborInfo& info)
{
    if (info.addr)
    {
        getIntfOrLog(interfacesByIdx, info.ifidx, [&](auto& intf) {
            intf.staticNeighbors.erase(*info.addr);
        });
    }
}

void Manager::addDefGw(unsigned ifidx, InAddrAny addr)
{
    getIntfOrLog(interfacesByIdx, ifidx, [&](auto& intf) {
        std::visit(
            [&](auto addr) {
                if constexpr (std::is_same_v<in_addr, decltype(addr)>)
                {
                    intf.EthernetInterfaceIntf::defaultGateway(
                        std::to_string(addr));
                }
                else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
                {
                    intf.EthernetInterfaceIntf::defaultGateway6(
                        std::to_string(addr));
                }
                else
                {
                    static_assert(!std::is_same_v<void, decltype(addr)>);
                }
            },
            addr);
    });
}

void Manager::removeDefGw(unsigned ifidx, InAddrAny addr)
{
    getIntfOrLog(interfacesByIdx, ifidx, [&](auto& intf) {
        std::visit(
            [&](auto addr) {
                if constexpr (std::is_same_v<in_addr, decltype(addr)>)
                {
                    if (intf.defaultGateway() == std::to_string(addr))
                    {
                        intf.EthernetInterfaceIntf::defaultGateway("");
                    }
                }
                else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
                {
                    if (intf.defaultGateway6() == std::to_string(addr))
                    {
                        intf.EthernetInterfaceIntf::defaultGateway6("");
                    }
                }
                else
                {
                    static_assert(!std::is_same_v<void, decltype(addr)>);
                }
            },
            addr);
    });
}

void Manager::createInterfaces()
{
    // clear all the interfaces first
    interfaces.clear();
    interfacesByIdx.clear();
    for (auto& info : system::getInterfaces())
    {
        addInterface(info);
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

void Manager::reloadConfigsNoRefresh()
{
    reloadTimer->restartOnce(reloadTimeout);
}

void Manager::reloadConfigs()
{
    reloadConfigsNoRefresh();
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
    if (refreshObjectTimer->isEnabled())
    {
        refreshObjectTimer->setRemaining(refreshTimeout);
    }
}

void Manager::handleAdminState(std::string_view state, unsigned ifidx)
{
    if (state == "initialized" || state == "linger")
    {
        systemdNetworkdEnabled.erase(ifidx);
    }
    else
    {
        bool managed = state != "unmanaged";
        systemdNetworkdEnabled.insert_or_assign(ifidx, managed);
        if (auto it = undiscoveredIntfInfo.find(ifidx);
            it != undiscoveredIntfInfo.end())
        {
            auto info = std::move(it->second);
            undiscoveredIntfInfo.erase(it);
            createInterface(info, managed);
        }
        else if (auto it = interfacesByIdx.find(ifidx);
                 it != interfacesByIdx.end())
        {
            it->second->EthernetInterfaceIntf::nicEnabled(managed);
        }
    }
}

} // namespace network
} // namespace phosphor
