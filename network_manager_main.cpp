#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include "config.h"
#include "network_manager.hpp"

int main(int argc, char *argv[])
{
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus Object Manager for the 'root' path of the network manager.
    sdbusplus::server::manager::manager objManager(bus, OBJ_NETWORK);

    phosphor::network::Manager manager(bus, OBJ_NETWORK);

    bus.request_name(BUSNAME_NETWORK);

    while(true)
    {
        bus.process_discard();
        bus.wait();
    }

    return 0;
}
