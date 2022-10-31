#include "rtnetlink_server.hpp"

#include "netlink.hpp"
#include "network_manager.hpp"
#include "rtnetlink.hpp"
#include "types.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

#include <memory>
#include <phosphor-logging/log.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/ops.hpp>
#include <string_view>

namespace phosphor
{
namespace network
{

extern std::unique_ptr<Timer> refreshObjectTimer;

namespace netlink
{

using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;

static bool shouldRefresh(const struct nlmsghdr& hdr,
                          std::string_view data) noexcept
{
    switch (hdr.nlmsg_type)
    {
        case RTM_NEWLINK:
        case RTM_DELLINK:
        case RTM_NEWADDR:
        case RTM_DELADDR:
            return true;
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
        {
            if (data.size() < sizeof(ndmsg))
            {
                return false;
            }
            const auto& ndm = *reinterpret_cast<const ndmsg*>(data.data());
            // We only want to refresh for static neighbors
            return ndm.ndm_state & NUD_PERMANENT;
        }
    }
    return false;
}

static void rthandler(Manager& m, bool n, std::string_view data)
{
    auto ret = netlink::gatewayFromRtm(data);
    if (!ret)
    {
        return;
    }
    auto ifIdx = std::get<unsigned>(*ret);
    auto it = m.interfacesByIdx.find(ifIdx);
    if (it == m.interfacesByIdx.end())
    {
        auto msg = fmt::format("Interface `{}` not found for route", ifIdx);
        log<level::ERR>(msg.c_str(), entry("IFIDX=%u", ifIdx));
        return;
    }
    std::visit(
        [&](auto addr) {
            if constexpr (std::is_same_v<in_addr, decltype(addr)>)
            {
                if (n)
                {
                    it->second->EthernetInterfaceIntf::defaultGateway(
                        std::to_string(addr));
                }
                else if (it->second->defaultGateway() == std::to_string(addr))
                {
                    it->second->EthernetInterfaceIntf::defaultGateway("");
                }
            }
            else if constexpr (std::is_same_v<in6_addr, decltype(addr)>)
            {
                if (n)
                {
                    it->second->EthernetInterfaceIntf::defaultGateway6(
                        std::to_string(addr));
                }
                else if (it->second->defaultGateway6() == std::to_string(addr))
                {
                    it->second->EthernetInterfaceIntf::defaultGateway6("");
                }
            }
            else
            {
                static_assert(!std::is_same_v<void, decltype(addr)>);
            }
        },
        std::get<InAddrAny>(*ret));
}

static void handler(Manager& m, const nlmsghdr& hdr, std::string_view data)
{
    if (shouldRefresh(hdr, data) && !refreshObjectTimer->isEnabled())
    {
        refreshObjectTimer->restartOnce(refreshTimeout);
    }
    switch (hdr.nlmsg_type)
    {
        case RTM_NEWROUTE:
            rthandler(m, true, data);
            break;
        case RTM_DELROUTE:
            rthandler(m, false, data);
            break;
    }
}

static void eventHandler(Manager& m, sdeventplus::source::IO&, int fd, uint32_t)
{
    receive(fd, [&](auto&&... args) {
        return handler(m, std::forward<decltype(args)>(args)...);
    });
}

static stdplus::ManagedFd makeSock()
{
    using namespace stdplus::fd;

    auto sock = socket(SocketDomain::Netlink, SocketType::Raw,
                       static_cast<stdplus::fd::SocketProto>(NETLINK_ROUTE));

    sock.fcntlSetfl(sock.fcntlGetfl().set(FileFlag::NonBlock));

    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                      RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_NEIGH;
    bind(sock, local);

    return sock;
}

Server::Server(sdeventplus::Event& event, Manager& manager) :
    sock(makeSock()),
    io(event, sock.get(), EPOLLIN | EPOLLET, [&](auto&&... args) {
        return eventHandler(manager, std::forward<decltype(args)>(args)...);
    })
{
}

} // namespace netlink
} // namespace network
} // namespace phosphor
