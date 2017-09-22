#include "rtnetlink_server.hpp"
#include "timer.hpp"
#include "types.hpp"
#include "util.hpp"


#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/types.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#include <phosphor-logging/log.hpp>

#include <memory>

namespace phosphor
{
namespace network
{

extern std::unique_ptr<phosphor::network::Timer> refreshObjectTimer;

namespace rtnetlink
{

using namespace std::chrono_literals;

#if 0
/* debug function to print the time */
void printTime()
{
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::cout << std::put_time(std::localtime(&now_c), "%c") << '\n';

}
#endif

/* Call Back for the sd event loop */
static int eventHandler(sd_event_source* es, int fd, uint32_t revents,
                        void* userdata)
{
    char buffer[phosphor::network::rtnetlink::BUFSIZE] {};
    int len {};

    auto netLinkHeader = reinterpret_cast<struct nlmsghdr*>(buffer);
    while ((len = recv(fd, netLinkHeader,
                        phosphor::network::rtnetlink::BUFSIZE, 0)) > 0)
    {
        for (; (NLMSG_OK(netLinkHeader, len)) &&
               (netLinkHeader->nlmsg_type != NLMSG_DONE);
                    netLinkHeader = NLMSG_NEXT(netLinkHeader, len))
        {
            if (netLinkHeader->nlmsg_type == RTM_NEWADDR ||
                netLinkHeader->nlmsg_type == RTM_DELADDR)
            {
                // starting the timer here to make sure that we don't want
                // create the child objects multiple times.
                if (refreshObjectTimer->isExpired())
                {
                    using namespace std::chrono;
                    auto time = duration_cast<microseconds>(refreshTimeout);
                    // if start timer throws exception then let the application
                    // crash
                    refreshObjectTimer->startTimer(time);
                } // end if
            } // end if

        } // end for

    } // end while

    return 0;
}

int Server::run()
{
    using namespace phosphor::logging;

    struct sockaddr_nl addr {};

    int fd = -1;
    phosphor::Descriptor smartSock(fd);

    int r {};

    sigset_t ss {};


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
    addr.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    if (bind(smartSock(), (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        r = -errno;
        goto finish;
    }

    r = sd_event_add_io(eventPtr.get(), nullptr,
                        smartSock(), EPOLLIN, eventHandler, nullptr);
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
