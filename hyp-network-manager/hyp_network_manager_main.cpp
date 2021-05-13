#include "config.h"

#include "hyp_network_manager.hpp"

#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdeventplus/event.hpp>
#include <string>

using namespace phosphor::logging;
using sdbusplus::exception::SdBusError;

constexpr char DEFAULT_HYP_OBJPATH[] =
    "/xyz/openbmc_project/network/hypervisor";
constexpr char DEFAULT_HYP_BUSNAME[] = "xyz.openbmc_project.Network.Hypervisor";

int main(int argc, char** argv)
{
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, DEFAULT_HYP_OBJPATH);

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Create hypervisor network manager dbus object
    phosphor::network::HypNetworkMgr manager(bus, event, DEFAULT_HYP_OBJPATH);

    bus.request_name(DEFAULT_HYP_BUSNAME);

    event.loop();
    return 0;
}
