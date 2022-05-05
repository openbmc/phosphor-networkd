#include "hyp_network_manager.hpp"

#include <net/if.h>

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

class TestHypNetworkManager : public testing::Test
{
  public:
    sdbusplus::bus::bus bus;
    HypNetworkMgr manager;
    sdeventplus::Event event = sdeventplus::Event::get_default();
    TestHypNetworkManager() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, event, "/xyz/openbmc_test/network/hypervisor")
    {
        manager.setDefaultBIOSTableAttrsOnIntf("if0");
        manager.setDefaultBIOSTableAttrsOnIntf("if1");
        manager.setDefaultHostnameInBIOSTableAttrs();
    }

    ~TestHypNetworkManager() = default;
};

TEST_F(TestHypNetworkManager, getDefaultBiosTableAttr)
{
    biosTableType biosAttrs = manager.getBIOSTableAttrs();
    auto itr = biosAttrs.find("vmi_if0_ipv4_method");
    if (itr != biosAttrs.end())
    {
        std::string biosAttrValue = std::get<std::string>(itr->second);
        EXPECT_EQ(biosAttrValue, "IPv4Static");
    }
}

TEST_F(TestHypNetworkManager, setHostnameInBiosTableAndGet)
{
    std::string attribute = "vmi_hostname";
    std::string value = "testHostname";
    manager.setBIOSTableAttr(attribute, value, "String");
    biosTableType biosAttrs = manager.getBIOSTableAttrs();
    auto itr = biosAttrs.find("vmi_hostname");
    if (itr != biosAttrs.end())
    {
        std::string biosAttrValue = std::get<std::string>(itr->second);
        EXPECT_EQ(biosAttrValue, value);
    }
}

} // namespace network
} // namespace phosphor
