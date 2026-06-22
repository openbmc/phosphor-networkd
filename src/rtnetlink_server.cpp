#include "rtnetlink_server.hpp"

#include "netlink.hpp"
#include "network_manager.hpp"
#include "rtnetlink.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <phosphor-logging/lg2.hpp>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/ops.hpp>

#include <optional>

namespace phosphor::network::netlink
{

inline void rthandler(std::string_view data, auto&& cb)
{
    auto ret = gatewayFromRtm(data);
    if (!ret)
    {
        return;
    }
    cb(std::get<unsigned>(*ret), std::get<stdplus::InAnyAddr>(*ret));
}

static std::optional<unsigned> getIfIdx(const nlmsghdr& hdr,
                                        std::string_view data)
{
    switch (hdr.nlmsg_type)
    {
        case RTM_NEWLINK:
        case RTM_DELLINK:
            return extractRtData<ifinfomsg>(data).ifi_index;
        case RTM_NEWADDR:
        case RTM_DELADDR:
            return extractRtData<ifaddrmsg>(data).ifa_index;
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
            return extractRtData<ndmsg>(data).ndm_ifindex;
        default:
            return std::nullopt;
    }
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
            default:
                lg2::debug("Ignoring unsupported netlink message type {TYPE}",
                           "TYPE", hdr.nlmsg_type);
                break;
        }
    }
    catch (const std::exception& e)
    {
        try
        {
            auto ifIdx = getIfIdx(hdr, data);
            if (ifIdx.has_value() && m.ignoredIntf.contains(*ifIdx))
            {
                // We don't want to log errors for ignored interfaces
                return;
            }
        }
        catch (const std::exception& idxErr)
        {
            lg2::debug(
                "Unable to determine interface index for netlink message type "
                "{TYPE}: {ERROR}",
                "TYPE", hdr.nlmsg_type, "ERROR", idxErr);
        }
        catch (...)
        {
            lg2::debug("Unable to determine interface index for netlink "
                       "message type {TYPE}",
                       "TYPE", hdr.nlmsg_type);
        }
        lg2::error("Failed handling netlink event: {ERROR}", "ERROR", e);
    }
    catch (...)
    {
        lg2::error("Failed handling netlink event with unknown exception");
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
