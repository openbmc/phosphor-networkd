#include "rtnetlink_server.hpp"

#include "netlink.hpp"
#include "network_manager.hpp"
#include "rtnetlink.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <phosphor-logging/log.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/ops.hpp>

namespace phosphor::network::netlink
{

using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;

inline void rthandler(std::string_view data, auto&& cb)
{
    auto ret = gatewayFromRtm(data);
    if (!ret)
    {
        return;
    }
    cb(std::get<unsigned>(*ret), std::get<InAddrAny>(*ret));
}

static void handler(Manager& m, const nlmsghdr& hdr, std::string_view data)
{
    try
    {
        switch (hdr.nlmsg_type)
        {
            case RTM_NEWLINK:
                m.addInterface(intfFromRtm(data));
                break;
            case RTM_DELLINK:
                m.removeInterface(intfFromRtm(data));
                break;
            case RTM_NEWROUTE:
                rthandler(data, [&](auto ifidx, auto addr) {
                    m.addDefGw(ifidx, addr);
                });
                break;
            case RTM_DELROUTE:
                rthandler(data, [&](auto ifidx, auto addr) {
                    m.removeDefGw(ifidx, addr);
                });
                break;
            case RTM_NEWADDR:
                m.addAddress(addrFromRtm(data));
                break;
            case RTM_DELADDR:
                m.removeAddress(addrFromRtm(data));
                break;
            case RTM_NEWNEIGH:
                m.addNeighbor(neighFromRtm(data));
                break;
            case RTM_DELNEIGH:
                m.removeNeighbor(neighFromRtm(data));
                break;
        }
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Failed handling netlink event: {}", e.what());
        log<level::ERR>(msg.c_str(), entry("ERROR=%s", e.what()));
    }
}

static void eventHandler(Manager& m, sdeventplus::source::IO&, int fd, uint32_t)
{
    auto cb = [&](auto&&... args) {
        return handler(m, std::forward<decltype(args)>(args)...);
    };
    while (receive(fd, cb) > 0)
        ;
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
    auto cb = [&](const nlmsghdr& hdr, std::string_view data) {
        handler(manager, hdr, data);
    };
    performRequest(NETLINK_ROUTE, RTM_GETLINK, NLM_F_DUMP, ifinfomsg{}, cb);
    performRequest(NETLINK_ROUTE, RTM_GETADDR, NLM_F_DUMP, ifaddrmsg{}, cb);
    performRequest(NETLINK_ROUTE, RTM_GETROUTE, NLM_F_DUMP, rtmsg{}, cb);
    performRequest(NETLINK_ROUTE, RTM_GETNEIGH, NLM_F_DUMP, ndmsg{}, cb);
}

} // namespace phosphor::network::netlink
