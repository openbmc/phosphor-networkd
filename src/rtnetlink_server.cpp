#include "rtnetlink_server.hpp"

#include "types.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

#include <memory>
#include <stdplus/fd/create.hpp>
#include <stdplus/fd/ops.hpp>
#include <string_view>

namespace phosphor
{
namespace network
{

extern std::unique_ptr<Timer> refreshObjectTimer;

namespace rtnetlink
{

static bool shouldRefresh(const struct nlmsghdr& hdr, std::string_view data)
{
    switch (hdr.nlmsg_type)
    {
        case RTM_NEWADDR:
        case RTM_DELADDR:
        case RTM_NEWROUTE:
        case RTM_DELROUTE:
        {
            return true;
        }
        case RTM_NEWNEIGH:
        case RTM_DELNEIGH:
        {
            struct ndmsg ndm;
            if (data.size() < sizeof(ndm))
            {
                return false;
            }
            memcpy(&ndm, data.data(), sizeof(ndm));
            // We only want to refresh for static neighbors
            return ndm.ndm_state & NUD_PERMANENT;
        }
    }

    return false;
}

/* Call Back for the sd event loop */
static void eventHandler(sdeventplus::source::IO&, int fd, uint32_t)
{
    std::array<char, BUFSIZE> buffer = {};
    int len{};

    auto netLinkHeader = reinterpret_cast<struct nlmsghdr*>(buffer.data());

    while ((len = recv(fd, netLinkHeader, buffer.size(), 0)) > 0)
    {
        for (; (NLMSG_OK(netLinkHeader, len)) &&
               (netLinkHeader->nlmsg_type != NLMSG_DONE);
             netLinkHeader = NLMSG_NEXT(netLinkHeader, len))
        {
            std::string_view data(
                reinterpret_cast<const char*>(NLMSG_DATA(netLinkHeader)),
                netLinkHeader->nlmsg_len - NLMSG_HDRLEN);
            if (shouldRefresh(*netLinkHeader, data))
            {
                // starting the timer here to make sure that we don't want
                // create the child objects multiple times.
                if (!refreshObjectTimer->isEnabled())
                {
                    // if start timer throws exception then let the application
                    // crash
                    refreshObjectTimer->restartOnce(refreshTimeout);
                } // end if
            }     // end if

        } // end for

        buffer.fill('\0');

        netLinkHeader = reinterpret_cast<struct nlmsghdr*>(buffer.data());
    } // end while
}

static stdplus::ManagedFd makeSock()
{
    using namespace stdplus::fd;

    auto sock = socket(SocketDomain::Netlink, SocketType::Raw,
                       static_cast<stdplus::fd::SocketProto>(NETLINK_ROUTE));

    sock.fcntlSetfl(sock.fcntlGetfl().set(FileFlag::NonBlock));

    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
                      RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_NEIGH;
    bind(sock, local);

    return sock;
}

Server::Server(sdeventplus::Event& event) :
    sock(makeSock()), io(event, sock.get(), EPOLLIN | EPOLLET, eventHandler)
{
}

} // namespace rtnetlink
} // namespace network
} // namespace phosphor
