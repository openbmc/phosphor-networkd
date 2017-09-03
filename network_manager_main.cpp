#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <memory>
#include <iostream>

#include <phosphor-logging/elog-errors.hpp>
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
                // TODO delete the below trace in later commit.
                std::cout << "Address Changed\n";

            } // end if

        } // end for

    } // end while

    return 0;
}

} // namespace rtnetlink


} // namespace network
} // namespace phosphor

int main(int argc, char *argv[])
{
    using namespace phosphor::logging;
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;

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
