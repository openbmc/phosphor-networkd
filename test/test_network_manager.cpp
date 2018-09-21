#include "mock_syscall.hpp"
#include "network_manager.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <exception>
#include <experimental/filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <sdbusplus/bus.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

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

    int getSize()
    {
        return manager.interfaces.size();
    }

    bool isInterfaceAdded(std::string intf)
    {
        return manager.interfaces.find(intf) != manager.interfaces.end()
                   ? true
                   : false;
    }
};

// getifaddrs will not return any interface
TEST_F(TestNetworkManager, NoInterface)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    bool caughtException = false;
    try
    {
        createInterfaces();
    }
    catch (InternalFailure& e)
    {
        caughtException = true;
    }

    EXPECT_EQ(true, caughtException);
}

// getifaddrs returns single interface.
TEST_F(TestNetworkManager, WithSingleInterface)
{
    bool caughtException = false;
    try
    {
        // Adds the following ip in the getifaddrs list.
        mock_addIP("igb1", "192.0.2.3", "255.255.255.128",
                   IFF_UP | IFF_RUNNING);

        // Now create the interfaces which will call the mocked getifaddrs
        // which returns the above interface detail.
        createInterfaces();
        EXPECT_EQ(1, getSize());
        EXPECT_EQ(true, isInterfaceAdded("igb1"));
    }
    catch (std::exception& e)
    {
        caughtException = true;
    }
    EXPECT_EQ(false, caughtException);
}

// getifaddrs returns two interfaces.
TEST_F(TestNetworkManager, WithMultipleInterfaces)
{
    try
    {
        mock_addIP("igb0", "192.0.2.2", "255.255.255.128",
                   IFF_UP | IFF_RUNNING);

        mock_addIP("igb1", "192.0.2.3", "255.255.255.128",
                   IFF_UP | IFF_RUNNING);

        createInterfaces();
        EXPECT_EQ(2, getSize());
        EXPECT_EQ(true, isInterfaceAdded("igb0"));
    }
    catch (std::exception& e)
    {
    }
}

} // namespace network
} // namespace phosphor
