#pragma once
#include "network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

class MockManager : public Manager
{
  public:
    MockManager(sdbusplus::bus_t& bus, const char* path,
                const std::string& dir) :
        Manager(bus, path, dir)
    {
    }

    MOCK_METHOD(void, reloadConfigs, (), (override));

    using Manager::handleAdminState;
};

} // namespace network
} // namespace phosphor
