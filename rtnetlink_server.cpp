#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#include <phosphor-logging/log.hpp>

#include "rtnetlink_server.hpp"
#include "types.hpp"
#include "util.hpp"

namespace phosphor
{
namespace network
{
namespace rtnetlink
{

int Server::run()
{
    using namespace phosphor::logging;

    struct sockaddr_nl addr {};
    sd_event* event = nullptr;

    phosphor::network::UniquePtr<sd_event> eventPtr(event, [](
                sd_event* event)
    {
        if (!event)
        {
            event = sd_event_unref(event);
        }
    });

    int fd = -1;
    phosphor::Descriptor smartSock(fd);

    int r {};

    sigset_t ss {};

    r = sd_event_default(&event);
    if (r < 0)
    {
        goto finish;
    }

    eventPtr.reset(event);
    event = nullptr;

    if (sigemptyset(&ss) < 0 || sigaddset(&ss, SIGTERM) < 0 ||
        sigaddset(&ss, SIGINT) < 0)
    {
        r = -errno;
        goto finish;
    }
    /* Block SIGTERM first, so that the event loop can handle it */
    if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0)
    {
        r = -errno;
        goto finish;
    }

    /* Let's make use of the default handler and "floating"
       reference features of sd_event_add_signal() */

    r = sd_event_add_signal(eventPtr.get(), NULL, SIGTERM, NULL, NULL);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_add_signal(eventPtr.get(), NULL, SIGINT, NULL, NULL);
    if (r < 0)
    {
        goto finish;
    }

    fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0)
    {
        r = -errno;
        goto finish;
    }

    smartSock.set(fd);
    fd = -1;

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_IFADDR;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        r = -errno;
        goto finish;
    }

    r = sd_event_add_io(eventPtr.get(), nullptr,
                        smartSock(), EPOLLIN, this->callback, nullptr);
    if (r < 0)
    {
        goto finish;
    }

    r = sd_event_loop(eventPtr.get());

finish:

    if (r < 0)
    {
        log<level::ERR>("Failure Occured in starting of server:",
                        entry("errno = %d", errno));
    }

    return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

} //rtnetlink
} //network
} //phosphor
