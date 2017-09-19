#include "config.h"
#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "timer.hpp"

#include <memory>

#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

namespace phosphor
{
namespace network
{

std::unique_ptr<phosphor::network::Manager> manager = nullptr;
std::unique_ptr<phosphor::network::Timer> refreshTimer = nullptr;

void refreshObjects()
{
    manager->createChildObjects();
}

} //namespace network
} //namespace phosphor

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

    phosphor::network::rtnetlink::Server svr(eventPtr);

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
        phosphor::network::manager->restartNetwork();
    }
    return svr.run();
}

