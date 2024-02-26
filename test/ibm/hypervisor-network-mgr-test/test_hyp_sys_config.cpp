#include "mock_hyp_sys_config.hpp"

#include <net/if.h>

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

class TestHypSysConfig : public testing::Test
{
  public:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    HypNetworkMgr manager;
    MockHypSysConfig sysConfigObj;
    TestHypSysConfig() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/network/hypervisor"),
        sysConfigObj(bus, "/xyz/openbmc_test/network/hypervisor/config",
                     manager)
    {
        manager.setDefaultHostnameInBIOSTableAttrs();
    }

    ~TestHypSysConfig() = default;
};

TEST_F(TestHypSysConfig, setAndGetHostName)
{
    std::string newHostName = "hostname1";
    sysConfigObj.setHostname(newHostName);

    biosTableType biosAttrs = manager.getBIOSTableAttrs();
    auto itr = biosAttrs.find("vmi_hostname");
    if (itr != biosAttrs.end())
    {
        std::string biosAttrValue = std::get<std::string>(itr->second);
        EXPECT_EQ(biosAttrValue, "hostname1");
    }

    std::string updatedHostName = sysConfigObj.getHostname();
    EXPECT_EQ(updatedHostName, newHostName);
}

} // namespace network
} // namespace phosphor
