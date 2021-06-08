#include "hyp_network_manager.hpp"

#include <fmt/format.h>

#include <phosphor-logging/log.hpp>
#include <sdeventplus/event.hpp>
#include <stdplus/signal.hpp>

using phosphor::logging::entry;
using phosphor::logging::level;
using phosphor::logging::log;

constexpr char DEFAULT_HYP_NW_OBJPATH[] =
    "/xyz/openbmc_project/network/hypervisor";
constexpr char HYP_DEFAULT_NETWORK_BUSNAME[] =
    "xyz.openbmc_project.Network.Hypervisor";

namespace phosphor
{
namespace network
{
std::unique_ptr<HypNetworkMgr> manager = nullptr;

int main()
{
    auto bus = sdbusplus::bus::new_default();

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager_t objManager(bus, DEFAULT_HYP_NW_OBJPATH);

    // Get default event loop
    auto event = sdeventplus::Event::get_default();
    stdplus::signal::block(SIGTERM);
    sdeventplus::source::Signal(event, SIGTERM, termCb).set_floating(true);

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Create hypervisor network manager dbus object
    manager =
        std::make_unique<HypNetworkMgr>(bus, event, DEFAULT_HYP_NW_OBJPATH);

    // Create the hypervisor eth interface objects
    manager->createIfObjects();

    // Create the hypervisor system config object
    manager->createSysConfObj();
    const SystemConfPtr& systemConfigObj = manager->getSystemConf();
    systemConfigObj->setHostName();

    bus.request_name(HYP_DEFAULT_NETWORK_BUSNAME);

    return event.loop();
}

} // namespace network
} // namespace phosphor

int main(int /*argc*/, char** /*argv*/)
{
    try
    {
        return phosphor::network::main();
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("FAILED: {}", e.what());
        log<level::ERR>(msg.c_str(), entry("ERROR", e.what()));
        return 1;
    }
}
