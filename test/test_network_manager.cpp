#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <exception>
#include <filesystem>
#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

namespace fs = std::filesystem;

class TestNetworkManager : public stdplus::gtest::TestWithTmp
{
  public:
    sdbusplus::bus_t bus;
    MockManager manager;
    TestNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/abc", CaseTmpDir())
    {
    }

    void createInterfaces()
    {
        manager.createInterfaces();
    }
};

// getifaddrs will not return any interface
TEST_F(TestNetworkManager, NoInterface)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    EXPECT_THROW(createInterfaces(), InternalFailure);
}
// getifaddrs returns single interface.
TEST_F(TestNetworkManager, WithSingleInterface)
{
    mock_clear();

    // Adds the following ip in the getifaddrs list.
    mock_addIF("igb1", 2);
    mock_addIP("igb1", "192.0.2.3", "255.255.255.128", IFF_UP | IFF_RUNNING);

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
    mock_addIP("igb0", "192.0.2.2", "255.255.255.128", IFF_UP | IFF_RUNNING);

    mock_addIF("igb1", 2);
    mock_addIP("igb1", "192.0.2.3", "255.255.255.128", IFF_UP | IFF_RUNNING);

    createInterfaces();
    EXPECT_EQ(2, manager.getInterfaceCount());
    EXPECT_EQ(true, manager.hasInterface("igb0"));
    EXPECT_EQ(true, manager.hasInterface("igb1"));
}
} // namespace network
} // namespace phosphor
