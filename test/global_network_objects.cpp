#include "mock_network_manager.hpp"
#include "types.hpp"

namespace phosphor
{

namespace network
{

std::unique_ptr<MockManager> manager = nullptr;
std::unique_ptr<Timer> reloadTimer = nullptr;

} // namespace network
} // namespace phosphor
