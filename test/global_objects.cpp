#include "mock_network_manager.hpp"
#include "types.hpp"

#include <sdeventplus/event.hpp>

namespace phosphor
{

namespace network
{

std::unique_ptr<MockManager> manager = nullptr;
std::unique_ptr<Timer> refreshObjectTimer;
std::unique_ptr<Timer> restartTimer;

/** @brief refresh the network objects. */
void refreshObjects()
{
    if (manager)
    {
        manager->createChildObjects();
    }
}

void initializeTimers()
{
    refreshObjectTimer = std::make_unique<Timer>(
        sdeventplus::Event::get_default(), std::bind(refreshObjects));
}

} // namespace network
} // namespace phosphor
