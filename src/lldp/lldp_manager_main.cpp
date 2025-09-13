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

    std::string lldpObjPath = "/xyz/openbmc_project/network/lldp";
    sdbusplus::server::manager_t objManager(bus, lldpObjPath.c_str());

    // Create LLDP Manager
    phosphor::network::lldp::Manager lldpManager(bus, event, lldpObjPath);

    // Request bus name
    bus.request_name(LLDP_DEFAULT_NETWORK_BUSNAME);

    return sdeventplus::utility::loopWithBus(event, bus);
}
