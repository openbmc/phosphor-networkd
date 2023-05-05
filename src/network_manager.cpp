#include "network_manager.hpp"

#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "system_queries.hpp"
#include "types.hpp"
#include "util.hpp"

#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <net/if.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message.hpp>
#include <stdplus/pinned.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>

constexpr char SYSTEMD_BUSNAME[] = "org.freedesktop.systemd1";
constexpr char SYSTEMD_PATH[] = "/org/freedesktop/systemd1";
constexpr char SYSTEMD_INTERFACE[] = "org.freedesktop.systemd1.Manager";

constexpr char NETWORKD_BUSNAME[] = "org.freedesktop.network1";
constexpr char NETWORKD_PATH[] = "/org/freedesktop/network1";
constexpr char NETWORKD_INTERFACE[] = "org.freedesktop.network1.Manager";

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

static constexpr const char enabledMatch[] =
    "type='signal',sender='org.freedesktop.network1',path_namespace='/org/"
    "freedesktop/network1/"
    "link',interface='org.freedesktop.DBus.Properties',member='"
    "PropertiesChanged',arg0='org.freedesktop.network1.Link',";

Manager::Manager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                 DelayedExecutor& reload, stdplus::zstring_view objPath,
                 const std::filesystem::path& confDir) :
    ManagerIface(bus, objPath.c_str(), ManagerIface::action::defer_emit),
    reload(reload), bus(bus), objPath(std::string(objPath)), confDir(confDir),
    systemdNetworkdEnabledMatch(
        bus, enabledMatch,
        [man = stdplus::PinnedRef(*this)](sdbusplus::message_t& m) {
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
        man.get().handleAdminState(state, ifidx);
    }
    catch (const std::exception& e)
    {
        lg2::error("AdministrativeState match parsing failed: {ERROR}", "ERROR",
                   e);
    }
        })
{
    reload.setCallback([&]() {
        for (auto& hook : reloadPreHooks)
        {
            try
            {
                hook();
            }
            catch (const std::exception& ex)
            {
                lg2::error("Failed executing reload hook, ignoring: {ERROR}",
                           "ERROR", ex);
            }
        }
        reloadPreHooks.clear();
        try
        {
            bus.get()
                .new_method_call(NETWORKD_BUSNAME, NETWORKD_PATH,
                                 NETWORKD_INTERFACE, "Reload")
                .call();
            lg2::info("Reloaded systemd-networkd");
        }
        catch (const sdbusplus::exception_t& ex)
        {
            lg2::error("Failed to reload configuration: {ERROR}", "ERROR", ex);
            reloadPostHooks.clear();
        }
        for (auto& hook : reloadPostHooks)
        {
            try
            {
                hook();
            }
            catch (const std::exception& ex)
            {
                lg2::error("Failed executing reload hook, ignoring: {ERROR}",
                           "ERROR", ex);
            }
        }
        reloadPostHooks.clear();
    });
    std::vector<
        std::tuple<int32_t, std::string, sdbusplus::message::object_path>>
        links;
    try
    {
        auto rsp = bus.get()
                       .new_method_call("org.freedesktop.network1",
                                        "/org/freedesktop/network1",
                                        "org.freedesktop.network1.Manager",
                                        "ListLinks")
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
            bus.get().new_method_call("org.freedesktop.network1", obj.c_str(),
                                      "org.freedesktop.DBus.Properties", "Get");
        req.append("org.freedesktop.network1.Link", "AdministrativeState");
        auto rsp = req.call();
        std::variant<std::string> val;
        rsp.read(val);
        handleAdminState(std::get<std::string>(val), ifidx);
    }

    std::filesystem::create_directories(confDir);
    systemConf = std::make_unique<phosphor::network::SystemConfiguration>(
        bus, (this->objPath / "config").str);
}

void Manager::createInterface(const AllIntfInfo& info, bool enabled)
{
    if (ignoredIntf.find(info.intf.idx) != ignoredIntf.end())
    {
        return;
    }
    if (auto it = interfacesByIdx.find(info.intf.idx);
        it != interfacesByIdx.end())
    {
        if (info.intf.name && *info.intf.name != it->second->interfaceName())
        {
            interfaces.erase(it->second->interfaceName());
            interfacesByIdx.erase(it);
        }
        else
        {
            it->second->updateInfo(info.intf);
            return;
        }
    }
    else if (info.intf.name)
    {
        auto it = interfaces.find(*info.intf.name);
        if (it != interfaces.end())
        {
            it->second->updateInfo(info.intf);
            return;
        }
    }
    if (!info.intf.name)
    {
        lg2::error("Can't create interface without name: {IFIDX}", "IFIDX",
                   info.intf.idx);
        return;
    }
    config::Parser config(config::pathForIntfConf(confDir, *info.intf.name));
    auto intf = std::make_unique<EthernetInterface>(
        bus, *this, info, objPath.str, config, enabled);
    intf->loadNameServers(config);
    intf->loadNTPServers(config);
    auto ptr = intf.get();
    interfaces.insert_or_assign(*info.intf.name, std::move(intf));
    interfacesByIdx.insert_or_assign(info.intf.idx, ptr);
}

void Manager::addInterface(const InterfaceInfo& info)
{
    if (info.flags & IFF_LOOPBACK)
    {
        ignoredIntf.emplace(info.idx);
        return;
    }
    if (info.name)
    {
        const auto& ignored = internal::getIgnoredInterfaces();
        if (ignored.find(*info.name) != ignored.end())
        {
            static std::unordered_set<std::string> ignored;
            if (!ignored.contains(*info.name))
            {
                ignored.emplace(*info.name);
                lg2::info("Ignoring interface {INTERFACE_NAME}",
                          "INTERFACE_NAME", *info.name);
            }
            ignoredIntf.emplace(info.idx);
            return;
        }
    }

    auto infoIt = intfInfo.find(info.idx);
    if (infoIt != intfInfo.end())
    {
        infoIt->second.intf = info;
    }
    else
    {
        infoIt = std::get<0>(intfInfo.emplace(info.idx, AllIntfInfo{info}));
    }

    if (auto it = systemdNetworkdEnabled.find(info.idx);
        it != systemdNetworkdEnabled.end())
    {
        createInterface(infoIt->second, it->second);
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
        ignoredIntf.erase(info.idx);
    }
    if (nit != interfaces.end())
    {
        interfaces.erase(nit);
    }
    intfInfo.erase(info.idx);
}

void Manager::addAddress(const AddressInfo& info)
{
    if (info.flags & IFA_F_DEPRECATED)
    {
        return;
    }
    if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
    {
        it->second.addrs.insert_or_assign(info.ifaddr, info);
        if (auto it = interfacesByIdx.find(info.ifidx);
            it != interfacesByIdx.end())
        {
            it->second->addAddr(info);
        }
    }
    else if (!ignoredIntf.contains(info.ifidx))
    {
        throw std::runtime_error(
            fmt::format("Interface `{}` not found for addr", info.ifidx));
    }
}

void Manager::removeAddress(const AddressInfo& info)
{
    if (auto it = interfacesByIdx.find(info.ifidx); it != interfacesByIdx.end())
    {
        it->second->addrs.erase(info.ifaddr);
        if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
        {
            it->second.addrs.erase(info.ifaddr);
        }
    }
}

void Manager::addNeighbor(const NeighborInfo& info)
{
    if (!(info.state & NUD_PERMANENT) || !info.addr)
    {
        return;
    }
    if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
    {
        it->second.staticNeighs.insert_or_assign(*info.addr, info);
        if (auto it = interfacesByIdx.find(info.ifidx);
            it != interfacesByIdx.end())
        {
            it->second->addStaticNeigh(info);
        }
    }
    else if (!ignoredIntf.contains(info.ifidx))
    {
        throw std::runtime_error(
            fmt::format("Interface `{}` not found for neigh", info.ifidx));
    }
}

void Manager::removeNeighbor(const NeighborInfo& info)
{
    if (!info.addr)
    {
        return;
    }
    if (auto it = intfInfo.find(info.ifidx); it != intfInfo.end())
    {
        it->second.staticNeighs.erase(*info.addr);
        if (auto it = interfacesByIdx.find(info.ifidx);
            it != interfacesByIdx.end())
        {
            it->second->staticNeighbors.erase(*info.addr);
        }
    }
}

void Manager::addDefGw(unsigned ifidx, InAddrAny addr)
{
    if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
    {
        std::visit(
            [&](auto addr) {
            if constexpr (std::is_same_v<in_addr, decltype(addr)>)
            {
                it->second.defgw4.emplace(addr);
            }
            else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
            {
                it->second.defgw6.emplace(addr);
            }
            else
            {
                static_assert(!std::is_same_v<void, decltype(addr)>);
            }
            },
            addr);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            std::visit(
                [&](auto addr) {
                if constexpr (std::is_same_v<in_addr, decltype(addr)>)
                {
                    it->second->EthernetInterfaceIntf::defaultGateway(
                        std::to_string(addr));
                }
                else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
                {
                    it->second->EthernetInterfaceIntf::defaultGateway6(
                        std::to_string(addr));
                }
                else
                {
                    static_assert(!std::is_same_v<void, decltype(addr)>);
                }
                },
                addr);
        }
    }
    else if (!ignoredIntf.contains(ifidx))
    {
        lg2::error("Interface {IFIDX} not found for gw", "IFIDX", ifidx);
    }
}

void Manager::removeDefGw(unsigned ifidx, InAddrAny addr)
{
    if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
    {
        std::visit(
            [&](auto addr) {
            if constexpr (std::is_same_v<in_addr, decltype(addr)>)
            {
                if (it->second.defgw4 == addr)
                {
                    it->second.defgw4.reset();
                }
            }
            else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
            {
                if (it->second.defgw6 == addr)
                {
                    it->second.defgw6.reset();
                }
            }
            else
            {
                static_assert(!std::is_same_v<void, decltype(addr)>);
            }
            },
            addr);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            std::visit(
                [&](auto addr) {
                if constexpr (std::is_same_v<in_addr, decltype(addr)>)
                {
                    if (it->second->defaultGateway() == std::to_string(addr))
                    {
                        it->second->EthernetInterfaceIntf::defaultGateway("");
                    }
                }
                else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
                {
                    if (it->second->defaultGateway6() == std::to_string(addr))
                    {
                        it->second->EthernetInterfaceIntf::defaultGateway6("");
                    }
                }
                else
                {
                    static_assert(!std::is_same_v<void, decltype(addr)>);
                }
                },
                addr);
        }
    }
}

ObjectPath Manager::vlan(std::string interfaceName, uint32_t id)
{
    if (id == 0 || id >= 4095)
    {
        lg2::error("VLAN ID {VLAN_ID} is not valid", "VLAN_ID", id);
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
    for (const auto& dirent : std::filesystem::directory_iterator(confDir))
    {
        std::error_code ec;
        std::filesystem::remove(dirent.path(), ec);
    }
    lg2::info("Network data purged.");
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
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            it->second->EthernetInterfaceIntf::nicEnabled(managed);
        }
        else if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
        {
            createInterface(it->second, managed);
        }
    }
}

} // namespace network
} // namespace phosphor
