#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <exception>
#include <experimental/filesystem>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

std::unique_ptr<Timer> refreshObjectTimer = nullptr;
std::unique_ptr<Timer> restartTimer = nullptr;

namespace fs = std::experimental::filesystem;

class TestNetworkManager : public testing::Test
{
  public:
    sdbusplus::bus::bus bus;
    Manager manager;
    std::string confDir;
    TestNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/abc", "/tmp")
    {
        setConfDir();
    }

    ~TestNetworkManager()
    {
        if (confDir != "")
        {
            fs::remove_all(confDir);
        }
    }

    void setConfDir()
    {
        char tmp[] = "/tmp/NetworkManager.XXXXXX";
        confDir = mkdtemp(tmp);
        manager.setConfDir(confDir);
    }

    void createInterfaces()
    {
        manager.createInterfaces();
    }
};

// getifaddrs will not return any interface
TEST_F(TestNetworkManager, NoInterface)
{
    mock_clear();
    createInterfaces();
    EXPECT_EQ(0, manager.getInterfaceCount());
}

// getifaddrs returns single interface.
TEST_F(TestNetworkManager, WithSingleInterface)
{
    mock_clear();
    mock_addIF("igb1", 2);

    // Now create the interfaces which will call the mocked getifaddrs
    // which returns the above interface detail.
    createInterfaces();
    EXPECT_EQ(1, manager.getInterfaceCount());
    EXPECT_EQ(true, manager.hasInterface("igb1"));
}

// getifaddrs returns two interfaces.
TEST_F(TestNetworkManager, WithMultipleInterfaces)
{
    mock_clear();
    mock_addIF("igb0", 1);
    mock_addIF("igb1", 2);

    createInterfaces();
    EXPECT_EQ(2, manager.getInterfaceCount());
    EXPECT_EQ(true, manager.hasInterface("igb0"));
    EXPECT_EQ(true, manager.hasInterface("igb1"));
}

} // namespace network
} // namespace phosphor
