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
        manager(bus, event, "/xyz/openbmc_test/network/hypervisor")
    {
    }

    ~TestHypNetworkManager() = default;
};

TEST_F(TestHypNetworkManager, setStringAttributeInBiosTableMap)
{
    std::string attribute = "vmi_if0_ipv4_ipaddr";
    std::string value = "9.9.9.3";
    manager.setBIOSTableAttr(attribute, value, "String");
    biosTableType biosAttrs = manager.getBIOSTableAttrs();
    auto itr = biosAttrs.find("vmi_if0_ipv4_ipaddr");
    if (itr != biosAttrs.end())
    {
        std::string biosAttrValue = std::get<std::string>(itr->second);
        EXPECT_EQ(biosAttrValue, value);
    }
}

TEST_F(TestHypNetworkManager, setIntAttributeInBiosTableMap)
{
    std::string attribute = "vmi_if0_ipv4_prefix_length";
    int64_t prefLen = 22;
    manager.setBIOSTableAttr(attribute, prefLen, "Integer");
    biosTableType biosAttrs = manager.getBIOSTableAttrs();
    auto itr = biosAttrs.find("vmi_if0_ipv4_prefix_length");
    if (itr != biosAttrs.end())
    {
        int64_t biosAttrValue = std::get<int64_t>(itr->second);
        EXPECT_EQ(biosAttrValue, prefLen);
    }
}

} // namespace network
} // namespace phosphor
