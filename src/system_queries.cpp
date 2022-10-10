#include "system_queries.hpp"

#include "netlink.hpp"
#include "util.hpp"

#include <fmt/format.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>

#include <algorithm>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <stdplus/fd/create.hpp>
#include <stdplus/raw.hpp>
#include <stdplus/util/cexec.hpp>
#include <string_view>
#include <system_error>

namespace phosphor::network::system
{

using std::literals::string_view_literals::operator""sv;
using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;

static stdplus::Fd& getIFSock()
{
    using namespace stdplus::fd;
    static auto fd =
        socket(SocketDomain::INet, SocketType::Datagram, SocketProto::IP);
    return fd;
}

static ifreq makeIFReq(std::string_view ifname)
{
    ifreq ifr = {};
    const auto copied = std::min<std::size_t>(ifname.size(), IFNAMSIZ - 1);
    std::copy_n(ifname.begin(), copied, ifr.ifr_name);
    return ifr;
}

static ifreq executeIFReq(std::string_view ifname, unsigned long cmd,
                          void* data = nullptr)
{
    ifreq ifr = makeIFReq(ifname);
    ifr.ifr_data = reinterpret_cast<char*>(data);
    getIFSock().ioctl(cmd, &ifr);
    return ifr;
}

inline auto optionalIFReq(stdplus::zstring_view ifname, unsigned long long cmd,
                          std::string_view cmdname, auto&& complete,
                          void* data = nullptr)
{
    ifreq ifr;
    std::optional<decltype(complete(ifr))> ret;
    try
    {
        ifr = executeIFReq(ifname, cmd, data);
    }
    catch (const std::system_error& e)
    {
        if (e.code() == std::errc::operation_not_supported)
        {
            auto msg = fmt::format("{} not supported on {}", cmdname, ifname);
            log<level::INFO>(msg.c_str(),
                             entry("INTERFACE=%s", ifname.c_str()));
            return ret;
        }
        throw;
    }
    ret.emplace(complete(ifr));
    return ret;
}

EthInfo getEthInfo(stdplus::zstring_view ifname)
{
    ethtool_cmd edata = {};
    edata.cmd = ETHTOOL_GSET;
    return optionalIFReq(
               ifname, SIOCETHTOOL, "ETHTOOL"sv,
               [&](const ifreq&) {
                   return EthInfo{.autoneg = edata.autoneg != 0,
                                  .speed = edata.speed};
               },
               &edata)
        .value_or(EthInfo{});
}

bool intfIsRunning(std::string_view ifname)
{
    return executeIFReq(ifname, SIOCGIFFLAGS).ifr_flags & IFF_RUNNING;
}

std::optional<unsigned> getMTU(stdplus::zstring_view ifname)
{
    return optionalIFReq(ifname, SIOCGIFMTU, "GMTU",
                         [](const ifreq& ifr) { return ifr.ifr_mtu; });
}

void setMTU(std::string_view ifname, unsigned mtu)
{
    auto ifr = makeIFReq(ifname);
    ifr.ifr_mtu = mtu;
    getIFSock().ioctl(SIOCSIFMTU, &ifr);
}

void setNICUp(std::string_view ifname, bool up)
{
    ifreq ifr = executeIFReq(ifname, SIOCGIFFLAGS);
    ifr.ifr_flags &= ~IFF_UP;
    ifr.ifr_flags |= up ? IFF_UP : 0;
    getIFSock().ioctl(SIOCSIFFLAGS, &ifr);
}

InterfaceInfo detail::parseInterface(const nlmsghdr& hdr, std::string_view msg)
{
    if (hdr.nlmsg_type != RTM_NEWLINK)
    {
        throw std::runtime_error("Not an interface msg");
    }
    auto ifinfo = stdplus::raw::extract<ifinfomsg>(msg);
    InterfaceInfo ret;
    ret.flags = ifinfo.ifi_flags;
    ret.idx = ifinfo.ifi_index;
    while (!msg.empty())
    {
        auto [hdr, data] = netlink::extractRtAttr(msg);
        if (hdr.rta_type == IFLA_IFNAME)
        {
            ret.name.emplace(data.begin(),
                             std::find(data.begin(), data.end(), '\0'));
        }
        else if (hdr.rta_type == IFLA_ADDRESS)
        {
            if (data.size() != sizeof(ether_addr))
            {
                // Some interfaces have IP addresses for their LLADDR
                continue;
            }
            ret.mac.emplace(stdplus::raw::copyFrom<ether_addr>(data));
        }
        else if (hdr.rta_type == IFLA_MTU)
        {
            ret.mtu.emplace(stdplus::raw::copyFrom<unsigned>(data));
        }
    }
    return ret;
}

bool detail::validateNewInterface(const InterfaceInfo& info)
{
    if (info.flags & IFF_LOOPBACK)
    {
        return false;
    }
    if (!info.name)
    {
        throw std::invalid_argument("Interface Dump missing name");
    }
    const auto& ignored = internal::getIgnoredInterfaces();
    if (ignored.find(*info.name) != ignored.end())
    {
        return false;
    }
    return true;
}

std::vector<InterfaceInfo> getInterfaces()
{
    std::vector<InterfaceInfo> ret;
    auto cb = [&](const nlmsghdr& hdr, std::string_view msg) {
        auto info = detail::parseInterface(hdr, msg);
        if (detail::validateNewInterface(info))
        {
            ret.emplace_back(std::move(info));
        }
    };
    ifinfomsg msg{};
    netlink::performRequest(NETLINK_ROUTE, RTM_GETLINK, NLM_F_DUMP, msg, cb);
    return ret;
}

} // namespace phosphor::network::system
