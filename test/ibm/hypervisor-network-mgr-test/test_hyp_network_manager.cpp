#include "mock_hyp_network_manager.hpp"

#include <net/if.h>

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

class TestHypNetworkManager : public testing::Test
{
  public:
    sdbusplus::bus::bus bus;
    MockHypManager manager;
    sdeventplus::Event event = sdeventplus::Event::get_default();
    TestHypNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, event, "/xyz/openbmc_test/hyp/abc")
    {
        createIfObjects();
    }

    ~TestHypNetworkManager() = default;
    void createIfObjects()
    {
        manager.interfaces.clear();
        manager.createIfObjects();
    }

    int getIntfCount()
    {
        ethIntfMapType interfaces = manager.getEthIntfList();
        return interfaces.size();
    }
};

TEST_F(TestHypNetworkManager, CheckInterfaceCount)
{
    createIfObjects();
    EXPECT_EQ(2, getIntfCount());
}

} // namespace network
} // namespace phosphor
