#include "network_manager.hpp"

#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "system_queries.hpp"
#include "types.hpp"
#include "util.hpp"

#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/message.hpp>
#include <stdplus/numeric/str.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/print.hpp>
#include <stdplus/str/cat.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <format>
#include <fstream>

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using std::literals::string_view_literals::operator""sv;

constexpr auto systemdBusname = "org.freedesktop.systemd1";
constexpr auto systemdObjPath = "/org/freedesktop/systemd1";
constexpr auto systemdInterface = "org.freedesktop.systemd1.Manager";
constexpr auto lldpFilePath = "/etc/lldpd.conf";
constexpr auto lldpService = "lldpd.service";

static constexpr const char enabledMatch[] =
    "type='signal',sender='org.freedesktop.network1',path_namespace='/org/"
    "freedesktop/network1/"
    "link',interface='org.freedesktop.DBus.Properties',member='"
    "PropertiesChanged',arg0='org.freedesktop.network1.Link',";

Manager::Manager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                 stdplus::PinnedRef<DelayedExecutor> reload,
                 stdplus::zstring_view objPath,
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
                auto ifidx =
                    stdplus::StrToInt<10, uint16_t>{}(obj.substr(sep + 3));
                const auto& state = std::get<std::string>(it->second);
                man.get().handleAdminState(state, ifidx);
            }
            catch (const std::exception& e)
            {
                lg2::error("AdministrativeState match parsing failed: {ERROR}",
                           "ERROR", e);
            }
        })
{
    reload.get().setCallback([self = stdplus::PinnedRef(*this)]() {
        for (auto& hook : self.get().reloadPreHooks)
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
        self.get().reloadPreHooks.clear();
        try
        {
            self.get()
                .bus.get()
                .new_method_call("org.freedesktop.network1",
                                 "/org/freedesktop/network1",
                                 "org.freedesktop.network1.Manager", "Reload")
                .call();
            lg2::info("Reloaded systemd-networkd");
        }
        catch (const sdbusplus::exception_t& ex)
        {
            lg2::error("Failed to reload configuration: {ERROR}", "ERROR", ex);
            self.get().reloadPostHooks.clear();
        }
        for (auto& hook : self.get().reloadPostHooks)
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
        self.get().reloadPostHooks.clear();
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
        stdplus::ToStrHandle<stdplus::IntToStr<10, unsigned>> tsh;
        auto obj =
            stdplus::strCat("/org/freedesktop/network1/link/_3"sv, tsh(ifidx));
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
        lg2::error("Can't create interface without name: {NET_IDX}", "NET_IDX",
                   info.intf.idx);
        return;
    }
    config::Parser config(config::pathForIntfConf(confDir, *info.intf.name));
    auto intf = std::make_unique<EthernetInterface>(
        bus, *this, info, objPath.str, config, enabled);
    intf->loadNameServers(config);
    intf->loadNTPServers(config);
    watchNTPServers(intf.get());
    watchTimeSyncActiveState(intf.get());
    auto ptr = intf.get();
    interfaces.insert_or_assign(*info.intf.name, std::move(intf));
    interfacesByIdx.insert_or_assign(info.intf.idx, ptr);
}

void Manager::addInterface(const InterfaceInfo& info)
{
    if (info.type != ARPHRD_ETHER)
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
                lg2::info("Ignoring interface {NET_INTF}", "NET_INTF",
                          *info.name);
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
            stdplus::print(stderr, "Removed interface desync detected\n");
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
            std::format("Interface `{}` not found for addr", info.ifidx));
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
            std::format("Interface `{}` not found for neigh", info.ifidx));
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

void Manager::addDefGw(unsigned ifidx, stdplus::InAnyAddr addr)
{
    if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
    {
        std::visit(
            [&](auto addr) {
                if constexpr (std::is_same_v<stdplus::In4Addr, decltype(addr)>)
                {
                    it->second.defgw4.emplace(addr);
                }
                else
                {
                    static_assert(
                        std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                    it->second.defgw6.emplace(addr);
                }
            },
            addr);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            std::visit(
                [&](auto addr) {
                    if constexpr (std::is_same_v<stdplus::In4Addr,
                                                 decltype(addr)>)
                    {
                        it->second->EthernetInterfaceIntf::defaultGateway(
                            stdplus::toStr(addr));
                    }
                    else
                    {
                        static_assert(
                            std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                        it->second->EthernetInterfaceIntf::defaultGateway6(
                            stdplus::toStr(addr));
                    }
                },
                addr);
        }
    }
    else if (!ignoredIntf.contains(ifidx))
    {
        lg2::error("Interface {NET_IDX} not found for gw", "NET_IDX", ifidx);
    }
}

void Manager::removeDefGw(unsigned ifidx, stdplus::InAnyAddr addr)
{
    if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
    {
        std::visit(
            [&](auto addr) {
                if constexpr (std::is_same_v<stdplus::In4Addr, decltype(addr)>)
                {
                    if (it->second.defgw4 == addr)
                    {
                        it->second.defgw4.reset();
                    }
                }
                else
                {
                    static_assert(
                        std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                    if (it->second.defgw6 == addr)
                    {
                        it->second.defgw6.reset();
                    }
                }
            },
            addr);
        if (auto it = interfacesByIdx.find(ifidx); it != interfacesByIdx.end())
        {
            std::visit(
                [&](auto addr) {
                    if constexpr (std::is_same_v<stdplus::In4Addr,
                                                 decltype(addr)>)
                    {
                        stdplus::ToStrHandle<stdplus::ToStr<stdplus::In4Addr>>
                            tsh;
                        if (it->second->defaultGateway() == tsh(addr))
                        {
                            it->second->EthernetInterfaceIntf::defaultGateway(
                                "");
                        }
                    }
                    else
                    {
                        static_assert(
                            std::is_same_v<stdplus::In6Addr, decltype(addr)>);
                        stdplus::ToStrHandle<stdplus::ToStr<stdplus::In6Addr>>
                            tsh;
                        if (it->second->defaultGateway6() == tsh(addr))
                        {
                            it->second->EthernetInterfaceIntf::defaultGateway6(
                                "");
                        }
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
        lg2::error("VLAN ID {NET_VLAN} is not valid", "NET_VLAN", id);
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
        if (auto it = intfInfo.find(ifidx); it != intfInfo.end())
        {
            createInterface(it->second, managed);
        }
    }
}

void Manager::writeLLDPDConfigurationFile()
{
    std::ofstream lldpdConfig(lldpFilePath);

    lldpdConfig << "configure system description BMC" << std::endl;
    lldpdConfig << "configure system ip management pattern eth*" << std::endl;
    for (const auto& intf : interfaces)
    {
        bool emitlldp = intf.second->emitLLDP();
        if (emitlldp)
        {
            lldpdConfig << "configure ports " << intf.second->interfaceName()
                        << " lldp status tx-only" << std::endl;
        }
        else
        {
            lldpdConfig << "configure ports " << intf.second->interfaceName()
                        << " lldp status disabled" << std::endl;
        }
    }

    lldpdConfig.close();
}

void Manager::reloadLLDPService()
{
    try
    {
        auto method = bus.get().new_method_call(
            systemdBusname, systemdObjPath, systemdInterface, "RestartUnit");
        method.append(lldpService, "replace");
        bus.get().call_noreply(method);
    }
    catch (const sdbusplus::exception_t& ex)
    {
        lg2::error("Failed to restart service {SERVICE}: {ERR}", "SERVICE",
                   lldpService, "ERR", ex);
    }
}

void Manager::watchNTPServers(EthernetInterface* intf)
{
    ntpServerMatch = std::make_unique<sdbusplus::bus::match::match>(
        bus,
        "type='signal',member='PropertiesChanged',interface='org.freedesktop."
        "DBus.Properties',path='/org/freedesktop/timesync1',"
        "arg0='org.freedesktop.timesync1.Manager'",
        [this, intf](sdbusplus::message::message& msg) {
            if (msg.is_method_error())
            {
                return;
            }

            std::string interface;
            std::map<std::string, std::variant<std::vector<std::string>>>
                changedProperties;
            std::vector<std::string> invalidatedProperties;
            msg.read(interface, changedProperties, invalidatedProperties);

            if (interface == "org.freedesktop.timesync1.Manager")
            {
                auto it = changedProperties.find("LinkNTPServers");
                if (it != changedProperties.end())
                {
                    lg2::info("NTP server ip updated in timesyncd");
                    config::Parser config(config::pathForIntfConf(
                        getConfDir(), intf->interfaceName()));
                    intf->loadNTPServers(config);
                }
            }
        });
}

void Manager::watchTimeSyncActiveState(EthernetInterface* intf)
{
    activeStateMatch = std::make_unique<sdbusplus::bus::match::match>(
        bus,
        "type='signal',member='PropertiesChanged',interface='org.freedesktop."
        "DBus.Properties',path='/org/freedesktop/systemd1/unit/systemd_2dtimesyncd_2eservice',"
        "arg0='org.freedesktop.systemd1.Unit'",
        [this, intf](sdbusplus::message::message& msg) {
            if (msg.is_method_error())
            {
                return;
            }

            std::string interface;
            std::map<std::string, std::variant<std::string>> changedProperties;
            std::vector<std::string> invalidatedProperties;
            msg.read(interface, changedProperties, invalidatedProperties);

            if (interface == "org.freedesktop.systemd1.Unit")
            {
                auto it = changedProperties.find("ActiveState");
                if (it != changedProperties.end())
                {
                    std::string activeState = std::get<std::string>(it->second);
                    if (activeState == "active" || activeState == "inactive")
                    {
                        config::Parser config(config::pathForIntfConf(
                            getConfDir(), intf->interfaceName()));
                        intf->loadNTPServers(config);
                    }
                }
            }
        });
}

} // namespace network
} // namespace phosphor
