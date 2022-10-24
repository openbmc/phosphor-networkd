#include "rtnetlink_server.hpp"

#include "netlink.hpp"
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

namespace netlink
{

static bool shouldRefresh(const struct nlmsghdr& hdr,
                          std::string_view data) noexcept
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

static void handler(const nlmsghdr& hdr, std::string_view data)
{
    if (shouldRefresh(hdr, data) && !refreshObjectTimer->isEnabled())
    {
        refreshObjectTimer->restartOnce(refreshTimeout);
    }
}

static void eventHandler(sdeventplus::source::IO&, int fd, uint32_t)
{
    receive(fd, handler);
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

} // namespace netlink
} // namespace network
} // namespace phosphor
