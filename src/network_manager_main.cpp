#include "config.h"

#ifdef SYNC_MAC_FROM_INVENTORY
#include "inventory_mac.hpp"
#endif
#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "types.hpp"

#include <fmt/format.h>

#include <functional>
#include <memory>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/signal.hpp>
#include <stdplus/signal.hpp>

using phosphor::logging::level;
using phosphor::logging::log;

constexpr char NETWORK_CONF_DIR[] = "/etc/systemd/network";
constexpr char DEFAULT_OBJPATH[] = "/xyz/openbmc_project/network";

namespace phosphor
{
namespace network
{

std::unique_ptr<Manager> manager = nullptr;
std::unique_ptr<Timer> reloadTimer = nullptr;

void reloadNetworkd()
{
    if (manager)
    {
        log<level::INFO>("Sending networkd reload");
        manager->doReloadConfigs();
        log<level::INFO>("Done networkd reload");
    }
}

void initializeTimers(sdeventplus::Event& event)
{
    reloadTimer = std::make_unique<Timer>(event, std::bind(reloadNetworkd));
}

void termCb(sdeventplus::source::Signal& signal, const struct signalfd_siginfo*)
{
    log<level::NOTICE>("Got TERM, exiting");
    signal.get_event().exit(0);
}

int main()
{
    auto event = sdeventplus::Event::get_default();
    stdplus::signal::block(SIGTERM);
    sdeventplus::source::Signal(event, SIGTERM, termCb).set_floating(true);

    initializeTimers(event);

    auto bus = sdbusplus::bus::new_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Add sdbusplus Object Manager for the 'root' path of the network manager.
    sdbusplus::server::manager_t objManager(bus, DEFAULT_OBJPATH);
    bus.request_name(DEFAULT_BUSNAME);

    manager = std::make_unique<Manager>(bus, DEFAULT_OBJPATH, NETWORK_CONF_DIR);

    // RTNETLINK event handler
    netlink::Server svr(event, *manager);

#ifdef SYNC_MAC_FROM_INVENTORY
    auto runtime = inventory::watch(bus, *manager);
#endif

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
        fmt::print(stderr, "FAILED: {}", e.what());
        fflush(stderr);
        return 1;
    }
}
