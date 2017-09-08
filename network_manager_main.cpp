#include "config.h"
#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "timer.hpp"
#include "types.hpp"

#include <chrono>
#include <functional>
#include <memory>

#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace phosphor
{
namespace network
{

std::unique_ptr<Timer> refreshTimer = nullptr;
std::unique_ptr<Manager> manager = nullptr;

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
                // create the child objects multiple times.
                if (refreshTimer->isExpired())
                {
                    using namespace std::chrono;
                    auto time = duration_cast<microseconds>(
                        std::chrono::milliseconds(NETWORK_CHANGE_TIMEOUT_SEC));

                    // if start timer throws exception then let the application
                    // crash
                    refreshTimer->startTimer(time);
                } // end if

            } // end if

        } // end for

    } // end while

    return 0;
}

} // namespace rtnetlink

void refreshObjects()
{
    phosphor::network::manager->createChildObjects();
}

} // namespace network
} // namespace phosphor

int main(int argc, char *argv[])
{
    using namespace phosphor::logging;

    std::function<void()> func(
            std::bind(&phosphor::network::refreshObjects));

    phosphor::network::refreshTimer =
        std::make_unique<phosphor::network::Timer>(func);

    auto bus = sdbusplus::bus::new_default();

    // Need sd_event to watch for OCC device errors
    sd_event* event = nullptr;
    auto r = sd_event_default(&event);
    if (r < 0)
    {
        log<level::ERR>("Error creating a default sd_event handler");
        return r;
    }

    phosphor::network::EventPtr eventPtr{event};
    event = nullptr;

    // Attach the bus to sd_event to service user requests
    bus.attach_event(eventPtr.get(), SD_EVENT_PRIORITY_NORMAL);

    // Add sdbusplus Object Manager for the 'root' path of the network manager.
    sdbusplus::server::manager::manager objManager(bus, OBJ_NETWORK);
    bus.request_name(BUSNAME_NETWORK);

    phosphor::network::manager =
        std::make_unique<phosphor::network::Manager>(bus,
                                                     OBJ_NETWORK,
                                                     NETWORK_CONF_DIR);

    phosphor::network::manager->createChildObjects();

    phosphor::network::rtnetlink::Server svr(
            eventPtr,
            phosphor::network::rtnetlink::eventHandler);
    return svr.run();
}
