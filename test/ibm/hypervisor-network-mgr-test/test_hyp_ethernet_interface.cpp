#include "mock_hyp_ethernet_interface.hpp"
#include "mock_hyp_network_manager.hpp"

#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{

class TestHypEthernetInterface : public testing::Test
{
  public:
    sdbusplus::bus::bus bus;
    MockHypManager manager;
    sdeventplus::Event event = sdeventplus::Event::get_default();

    MockHypEthernetInterface interface;
    TestHypEthernetInterface() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, event, "/xyz/openbmc_test/network/hypervisor"),
        interface(makeInterface(bus, manager))
    {
        manager.setDefaultBIOSTableAttrs();
        interface.createIPAddrObj();
    }

    static MockHypEthernetInterface makeInterface(sdbusplus::bus::bus& bus,
                                                  MockHypManager& manager)
    {
        return {bus, "/xyz/openbmc_test/network/hypervisor/eth0", "eth0",
                manager};
    }

    bool isIPObjExist(const std::string& intf, const std::string& ipaddress)
    {
        auto it = interface.addrs.find(intf);
        if (it != interface.addrs.end())
        {
            if (ipaddress == (it->second)->address())
            {
                return true;
            }
        }
        return false;
    }

    bool deleteIPObj(const std::string& intf, const std::string& ipaddress)
    {
        auto it = interface.addrs.find(intf);
        if (it == interface.addrs.end())
        {
            return false;
        }

        if (ipaddress == (it->second)->address())
        {
            interface.addrs.erase(intf);
            return true;
        }
        return false;
    }
};

TEST_F(TestHypEthernetInterface, AddIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    bool createip = interface.createIP(interface, "eth0", addressType,
                                       "10.10.10.10", 16, "10.10.10.1");
    if (createip)
    {
        EXPECT_EQ(true, isIPObjExist("eth0", "10.10.10.10"));
    }
}

TEST_F(TestHypEthernetInterface, AddMultipleAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    bool createip1 = interface.createIP(interface, "eth0", addressType,
                                        "10.10.10.10", 16, "10.10.10.1");
    if (createip1)
    {
        bool createip2 = interface.createIP(interface, "eth0", addressType,
                                            "20.20.20.20", 16, "20.20.20.1");
        if (createip2)
        {
            EXPECT_EQ(false, isIPObjExist("eth0", "10.10.10.10"));
            EXPECT_EQ(true, isIPObjExist("eth0", "20.20.20.20"));
        }
    }
}

TEST_F(TestHypEthernetInterface, DeleteIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    bool createip = interface.createIP(interface, "eth0", addressType,
                                       "20.20.20.20", 16, "20.20.20.1");
    if (createip)
    {
        EXPECT_EQ(true, deleteIPObj("eth0", "20.20.20.20"));
        EXPECT_EQ(false, isIPObjExist("eth0", "20.20.20.20"));
    }
}

TEST_F(TestHypEthernetInterface, DeleteInvalidIPAddress)
{
    EXPECT_EQ(false, deleteIPObj("eth0", "10.10.10.10"));
}
} // namespace network
} // namespace phosphor
