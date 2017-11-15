#include "config.h"
#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "timer.hpp"
#include "watch.hpp"
#include "dns_updater.hpp"

#include <linux/netlink.h>

#include <memory>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

std::unique_ptr<phosphor::network::Manager> manager = nullptr;
std::unique_ptr<phosphor::network::Timer> refreshObjectTimer = nullptr;
std::unique_ptr<phosphor::network::Timer> restartTimer = nullptr;

/** @brief refresh the network objects. */
void refreshObjects()
{
    using namespace phosphor::logging;
    if (manager)
    {
        log<level::INFO>("Refreshing the objects.");
        manager->createChildObjects();
        log<level::INFO>("Refreshing complete.");
    }
}

/** @brief restart the systemd networkd. */
void restartNetwork()
{
    restartSystemdUnit("systemd-networkd.service");
}

} //namespace network
} //namespace phosphor

void initializeTimers()
{
    std::function<void()> refreshFunc(
            std::bind(&phosphor::network::refreshObjects));

    std::function<void()> restartFunc(
            std::bind(&phosphor::network::restartNetwork));

    phosphor::network::refreshObjectTimer =
        std::make_unique<phosphor::network::Timer>(refreshFunc);

    phosphor::network::restartTimer =
        std::make_unique<phosphor::network::Timer>(restartFunc);
}

void createNetLinkSocket(phosphor::Descriptor& smartSock)
{
    using namespace phosphor::logging;
    using InternalFailure = sdbusplus::xyz::openbmc_project::Common::
                                    Error::InternalFailure;
    //RtnetLink socket
    int fd = -1;
    fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0)
    {
        auto r = -errno;
        log<level::ERR>("Unable to create the net link socket",
                        entry("ERRNO=%d", r));
        elog<InternalFailure>();
    }
    smartSock.set(fd);
}



int main(int argc, char *argv[])
{
    using namespace phosphor::logging;

    initializeTimers();

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

    // create the network interface dbus objects and system config
    phosphor::network::manager->createChildObjects();

    // create the default network files if the network file
    // is not there for any interface.
    // Parameter false means don't create the network
    // files forcefully.
    if (phosphor::network::manager->createDefaultNetworkFiles(false))
    {
        // if files created restart the network.
        // don't need to call the create child objects as eventhandler
        // will create it.
        phosphor::network::restartNetwork();
    }

    //RtnetLink socket
    phosphor::Descriptor smartSock;
    createNetLinkSocket(smartSock);

    // RTNETLINK event handler
    phosphor::network::rtnetlink::Server svr(eventPtr, smartSock);

    // DNS entry handler
    phosphor::network::inotify::Watch watch(eventPtr, DNS_ENTRY_FILE,
            std::bind(&phosphor::network::dns::updater::processDNSEntries,
                std::placeholders::_1));

    // At this point, we have registered for the notifications for future
    // events. However, if the file is already populated before this, then
    // they won't ever get notified and thus we need to read once before
    // waiting on change events
    phosphor::network::dns::updater::processDNSEntries(DNS_ENTRY_FILE);

    sd_event_loop(eventPtr.get());
}

