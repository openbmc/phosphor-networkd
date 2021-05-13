#include "hyp_network_manager.hpp"

#include <sdeventplus/event.hpp>

constexpr char DEFAULT_HYP_NW_OBJPATH[] =
    "/xyz/openbmc_project/network/hypervisor";
constexpr char HYP_DEFAULT_NETWORK_BUSNAME[] =
    "xyz.openbmc_project.Network.Hypervisor";

int main(int /*argc*/, char** /*argv*/)
{
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, DEFAULT_HYP_NW_OBJPATH);

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Create hypervisor network manager dbus object
    phosphor::network::HypNetworkMgr manager(bus, event,
                                             DEFAULT_HYP_NW_OBJPATH);

    bus.request_name(HYP_DEFAULT_NETWORK_BUSNAME);

    event.loop();
    return 0;
}
