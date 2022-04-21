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
        createIPObj();
    }

    static MockHypEthernetInterface makeInterface(sdbusplus::bus::bus& bus,
                                                  MockHypManager& manager)
    {
        return {bus, "/xyz/openbmc_test/network/hypervisor/eth0", "eth0",
                manager};
    }

    void createIPObj()
    {
        interface.createIPAddressObjects();
    }

    bool isIPObjectExist(const std::string& ipaddress)
    {
        auto it = interface.addrs.find(ipaddress);
        if (it != interface.addrs.end())
        {
            return true;
        }
        return false;
    }

    bool deleteIPObject(const std::string& ipaddress)
    {
        auto it = interface.addrs.find(ipaddress);
        if (it == interface.addrs.end())
        {
            return false;
        }
        interface.addrs.erase(it);
        return true;
    }

    void createIPObject(IP::Protocol addressType, const std::string& ipaddress,
                        uint8_t prefixLength, const std::string& gateway)
    {
        interface.ip(addressType, ipaddress, prefixLength, gateway);
    }
};

TEST_F(TestHypEthernetInterface, AddIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16, "10.10.10.1");
    EXPECT_EQ(true, isIPObjectExist("10.10.10.10"));
}

TEST_F(TestHypEthernetInterface, AddMultipleAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16, "10.10.10.1");
    createIPObject(addressType, "20.20.20.20", 16, "20.20.20.1");
    EXPECT_EQ(false, isIPObjectExist("10.10.10.10"));
    EXPECT_EQ(true, isIPObjectExist("20.20.20.20"));
}

TEST_F(TestHypEthernetInterface, DeleteIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "20.20.20.20", 16, "20.20.20.1");
    EXPECT_EQ(true, deleteIPObject("20.20.20.20"));
    EXPECT_EQ(false, isIPObjectExist("20.20.20.20"));
}

TEST_F(TestHypEthernetInterface, DeleteInvalidIPAddress)
{
    EXPECT_EQ(false, deleteIPObject("10.10.10.10"));
}
} // namespace network
} // namespace phosphor
