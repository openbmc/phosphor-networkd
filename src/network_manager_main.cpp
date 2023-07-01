#include "config.h"

#ifdef SYNC_MAC_FROM_INVENTORY
#include "inventory_mac.hpp"
#endif
#include "network_manager.hpp"
#include "rtnetlink_server.hpp"
#include "types.hpp"

#include <fmt/format.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/clock.hpp>
#include <sdeventplus/event.hpp>
#include <sdeventplus/source/signal.hpp>
#include <sdeventplus/utility/sdbus.hpp>
#include <sdeventplus/utility/timer.hpp>
#include <stdplus/pinned.hpp>
#include <stdplus/signal.hpp>

#include <chrono>

constexpr char DEFAULT_OBJPATH[] = "/xyz/openbmc_project/network";

namespace phosphor::network
{

class TimerExecutor : public DelayedExecutor
{
  private:
    using Timer = sdeventplus::utility::Timer<sdeventplus::ClockId::Monotonic>;

  public:
    TimerExecutor(sdeventplus::Event& event, std::chrono::milliseconds delay) :
        delay(delay), timer(event, nullptr)
    {}

    void schedule() override
    {
        timer.restartOnce(delay);
    }

    void setCallback(fu2::unique_function<void()>&& cb) override
    {
        timer.set_callback([cb = std::move(cb)](Timer&) mutable { cb(); });
    }

  private:
    std::chrono::milliseconds delay;
    Timer timer;
};

void termCb(sdeventplus::source::Signal& signal, const struct signalfd_siginfo*)
{
    lg2::notice("Received request to terminate, exiting");
    signal.get_event().exit(0);
}

int main()
{
    auto event = sdeventplus::Event::get_default();
    stdplus::signal::block(SIGTERM);
    sdeventplus::source::Signal(event, SIGTERM, termCb).set_floating(true);

    stdplus::Pinned bus = sdbusplus::bus::new_default();
    sdbusplus::server::manager_t objManager(bus, DEFAULT_OBJPATH);

    stdplus::Pinned<TimerExecutor> reload(event, std::chrono::seconds(3));
    stdplus::Pinned<Manager> manager(bus, reload, DEFAULT_OBJPATH,
                                     "/etc/systemd/network");
    netlink::Server svr(event, manager);

#ifdef SYNC_MAC_FROM_INVENTORY
    auto runtime = inventory::watch(bus, manager);
#endif

    bus.request_name(DEFAULT_BUSNAME);
    return sdeventplus::utility::loopWithBus(event, bus);
}

} // namespace phosphor::network

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
