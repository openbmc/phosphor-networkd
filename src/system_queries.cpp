#include "system_queries.hpp"

#include <fmt/format.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>

#include <algorithm>
#include <optional>
#include <phosphor-logging/log.hpp>
#include <stdexcept>
#include <stdplus/fd/create.hpp>
#include <stdplus/util/cexec.hpp>
#include <string_view>

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
    auto ukey = std::make_tuple(std::string(ifname), cmd);
    static std::unordered_set<std::tuple<std::string, unsigned long long>>
        unsupported;
    try
    {
        ifr = executeIFReq(ifname, cmd, data);
    }
    catch (const std::system_error& e)
    {
        if (e.code() == std::errc::operation_not_supported)
        {
            if (unsupported.find(ukey) == unsupported.end())
            {
                unsupported.emplace(std::move(ukey));
                auto msg =
                    fmt::format("{} not supported on {}", cmdname, ifname);
                log<level::INFO>(msg.c_str(),
                                 entry("INTERFACE=%s", ifname.c_str()));
            }
            return ret;
        }
        throw;
    }
    unsupported.erase(ukey);
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

} // namespace phosphor::network::system
