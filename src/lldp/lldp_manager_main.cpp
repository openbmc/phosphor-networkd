#include "lldp_config.h"

#include "lldp_manager.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/utility/sdbus.hpp>

int main()
{
    auto bus = sdbusplus::bus::new_default();
    auto event = sdeventplus::Event::get_default();

    sdbusplus::server::manager_t objManager(bus, LLDP_OBJECT_PATH);

    // Create LLDP Manager
    phosphor::network::lldp::LLDPManager lldpManager(bus, event);

    // Request bus name
    bus.request_name(LLDP_DEFAULT_BUSNAME);

    return sdeventplus::utility::loopWithBus(event, bus);
}
