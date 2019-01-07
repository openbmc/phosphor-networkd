#include "config.h"

#include "network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

class MockManager : public phosphor::network::Manager
{
  public:
    MockManager(sdbusplus::bus::bus& bus, const char* path,
                const std::string& dir) :
        phosphor::network::Manager(bus, path, dir)
    {
    }

    MOCK_METHOD1(restartSystemdUnit, void(const std::string& service));
};

} // namespace network
} // namespace phosphor
