#include "config.h"
#include "rtnetlink_server.hpp"
#include "timer.hpp"
#include "types.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <chrono>
#include <functional>
#include <memory>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>

#include <sdbusplus/bus.hpp>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace phosphor
{
namespace network
{

std::unique_ptr<phosphor::network::Timer> timer = nullptr;
sdbusplus::bus::bus bus = sdbusplus::bus::new_default();

constexpr auto service = "xyz.openbmc_project.Network";
constexpr auto root = "/xyz/openbmc_project/network";
constexpr auto refreshInterface = "xyz.openbmc_project.Network.Internal.Refresh";

namespace rtnetlink
{


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
                // multiple dbus calls for an interface as interface may have
                // more then one IP.
                if (timer->isExpired())
                {
                    using namespace std::chrono;
                    auto time = duration_cast<microseconds>(
                            std::chrono::milliseconds(NETWORK_CHANGE_TIMEOUT_MSEC));
                    // if start timer throws exception then let the application
                    // crash
                    timer->startTimer(time);

                } // end if

            } // end if

        } // end for

    } // end while

    return 0;
}

} // namespace rtnetlink

void timerCallback()
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

    auto busMethod = bus.new_method_call(
            service,
            root,
            refreshInterface,
            "Refresh");

    auto reply = bus.call(busMethod);

    if (reply.is_method_error())
    {
        log<level::ERR>("Failed to execute method",
                        entry("METHOD=%s", "Refresh"),
                        entry("PATH=%s", root),
                        entry("INTERFACE=%s", refreshInterface));
        elog<InternalFailure>();
    }

}

} // namespace network
} // namespace phosphor

int main(int argc, char* argv[])
{
    std::function<void()> func(
            std::bind(&phosphor::network::timerCallback));

    phosphor::network::timer =
        std::make_unique<phosphor::network::Timer>(func);

    phosphor::network::rtnetlink::Server svr(
            phosphor::network::rtnetlink::eventHandler);
    return svr.run();
}
