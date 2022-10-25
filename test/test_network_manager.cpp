#include "config_parser.hpp"
#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <filesystem>
#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using ::testing::Key;
using ::testing::UnorderedElementsAre;

class TestNetworkManager : public stdplus::gtest::TestWithTmp
{
  protected:
    sdbusplus::bus_t bus;
    MockManager manager;
    TestNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/abc", CaseTmpDir())
    {
        system::mock_clear();
    }

    void createInterfaces()
    {
        manager.createInterfaces();
    }

    void deleteVLAN(std::string_view ifname)
    {
        manager.interfaces.find(ifname)->second->vlan->delete_();
    }
};

// getifaddrs will not return any interface
TEST_F(TestNetworkManager, NoInterface)
{
    createInterfaces();
    EXPECT_TRUE(manager.interfaces.empty());
}
// getifaddrs returns single interface.
TEST_F(TestNetworkManager, WithSingleInterface)
{
    // Adds the following ip in the getifaddrs list.
    system::mock_addIF({.idx = 2, .flags = 0, .name = "igb1"});

    // Now create the interfaces which will call the mocked getifaddrs
    // which returns the above interface detail.
    createInterfaces();
    EXPECT_THAT(manager.interfaces, UnorderedElementsAre(Key("igb1")));
}

// getifaddrs returns two interfaces.
TEST_F(TestNetworkManager, WithMultipleInterfaces)
{
    system::mock_addIF({.idx = 1, .flags = 0, .name = "igb0"});
    system::mock_addIF({.idx = 2, .flags = 0, .name = "igb1"});

    createInterfaces();
    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("igb0"), Key("igb1")));
}

TEST_F(TestNetworkManager, WithVLAN)
{
    EXPECT_THROW(manager.vlan("", 8000), std::exception);
    EXPECT_THROW(manager.vlan("", 0), std::exception);
    EXPECT_THROW(manager.vlan("eth0", 2), std::exception);

    system::mock_addIF({.idx = 1, .flags = 0, .name = "eth0"});
    manager.createInterfaces();
    EXPECT_NO_THROW(manager.vlan("eth0", 2));
    EXPECT_NO_THROW(manager.vlan("eth0", 4094));
    EXPECT_THAT(
        manager.interfaces,
        UnorderedElementsAre(Key("eth0"), Key("eth0.2"), Key("eth0.4094")));
    auto netdev1 = config::pathForIntfDev(CaseTmpDir(), "eth0.2");
    auto netdev2 = config::pathForIntfDev(CaseTmpDir(), "eth0.4094");
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev1));
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev2));

    deleteVLAN("eth0.2");
    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("eth0"), Key("eth0.4094")));
    EXPECT_FALSE(std::filesystem::is_regular_file(netdev1));
    EXPECT_TRUE(std::filesystem::is_regular_file(netdev2));
}

} // namespace network
} // namespace phosphor
