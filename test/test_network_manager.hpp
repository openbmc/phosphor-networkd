#pragma once
#include "network_manager.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace network
{

struct MockExecutor : DelayedExecutor
{
    MOCK_METHOD((void), schedule, (), (override));
    MOCK_METHOD((void), setCallback, (fu2::unique_function<void()>&&),
                (override));
};

struct TestManagerData
{
    MockExecutor mockReload;
    fu2::unique_function<void()> reloadCb;

    inline MockExecutor& reloadForManager()
    {
        EXPECT_CALL(mockReload, setCallback(testing::_))
            .WillOnce([&](fu2::unique_function<void()>&& cb) {
                reloadCb = std::move(cb);
            });
        return mockReload;
    }
};

struct TestManager : TestManagerData, Manager
{
    inline TestManager(stdplus::PinnedRef<sdbusplus::bus_t> bus,
                       stdplus::zstring_view path,
                       const std::filesystem::path& dir) :
        Manager(bus, reloadForManager(), path, dir)
    {}

    using Manager::handleAdminState;
};

} // namespace network
} // namespace phosphor
