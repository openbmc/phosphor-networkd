#include "config_parser.hpp"
#include "mock_network_manager.hpp"

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
    }

    void deleteVLAN(std::string_view ifname)
    {
        manager.interfaces.find(ifname)->second->vlan->delete_();
    }
};

TEST_F(TestNetworkManager, NoInterface)
{
    EXPECT_TRUE(manager.interfaces.empty());
}

TEST_F(TestNetworkManager, WithSingleInterface)
{
    manager.addInterface({.idx = 2, .flags = 0, .name = "igb1"});
    manager.handleAdminState("managed", 2);

    // Now create the interfaces which will call the mocked getifaddrs
    // which returns the above interface detail.
    EXPECT_THAT(manager.interfaces, UnorderedElementsAre(Key("igb1")));
}

// getifaddrs returns two interfaces.
TEST_F(TestNetworkManager, WithMultipleInterfaces)
{
    manager.addInterface({.idx = 1, .flags = 0, .name = "igb0"});
    manager.handleAdminState("managed", 1);
    manager.handleAdminState("unmanaged", 2);
    manager.addInterface({.idx = 2, .flags = 0, .name = "igb1"});

    EXPECT_THAT(manager.interfaces,
                UnorderedElementsAre(Key("igb0"), Key("igb1")));
}

TEST_F(TestNetworkManager, WithVLAN)
{
    EXPECT_THROW(manager.vlan("", 8000), std::exception);
    EXPECT_THROW(manager.vlan("", 0), std::exception);
    EXPECT_THROW(manager.vlan("eth0", 2), std::exception);

    manager.addInterface({.idx = 1, .flags = 0, .name = "eth0"});
    manager.handleAdminState("managed", 1);
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
