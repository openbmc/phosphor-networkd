#include "network_manager.hpp"
#include "mock_syscall.hpp"
#include "config_parser.hpp"

#include <gtest/gtest.h>
#include <sdbusplus/bus.hpp>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <exception>

namespace phosphor
{
namespace network
{

class TestVlanInterface : public testing::Test
{
    public:

        sdbusplus::bus::bus bus;
        Manager manager;
        EthernetInterface interface;
        TestVlanInterface()
            : bus(sdbusplus::bus::new_default()),
              manager(bus, "/xyz/openbmc_test/network"),
              interface(bus, "/xyz/openbmc_test/network/test0", false, manager)

        {
              interface.setConfDir("/tmp/network/");
        }

        void createVlan(uint32_t vlanID)
        {
            interface.createVLAN(vlanID);
        }

        void deleteVlan(const std::string& interfaceName)
        {
            interface.deleteVLANObject(interfaceName);
        }

        int countIPObjects()
        {
            return interface.getAddresses().size();
        }

        bool isIPObjectExist(const std::string& ipaddress)
        {
            auto address = interface.getAddresses().find(ipaddress);
            if (address == interface.getAddresses().end())
            {
                return false;
            }
            return true;

        }

        bool deleteIPObject(const std::string& ipaddress)
        {
            auto address = interface.getAddresses().find(ipaddress);
            if (address == interface.getAddresses().end())
            {
                return false;
            }
            address->second->delete_();
            return true;
        }

        void createIPObject(IP::Protocol addressType,
                            const std::string& ipaddress,
                            uint8_t subnetMask,
                            const std::string& gateway)
        {
            interface.iP(addressType,
                         ipaddress,
                         subnetMask,
                         gateway
                        );

        }

        bool isValueFound(const std::vector<std::string>& values,
                          const std::string& expectedValue)
        {
            for (const auto& value : values)
            {
                if (expectedValue == value)
                {
                    return  true;
                }
            }
            return false;
        }
};

TEST_F(TestVlanInterface, createVLAN)
{
    createVlan(50);
    config::Parser parser("/tmp/network/test0.50.netdev");
    auto values = parser.getValues("NetDev", "Name");
    std::string expectedValue = "test0.50";
    bool found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("NetDev", "Kind");
    expectedValue = "vlan";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("VLAN", "Id");
    expectedValue = "50";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

}

TEST_F(TestVlanInterface, deleteVLAN)
{
    deleteVlan("test0.50");
    bool fileFound = false;
    if (fs::is_regular_file("/tmp/network/test0.50.netdev"))
    {
       fileFound = true;
    }
    EXPECT_EQ(fileFound, false);
}

TEST_F(TestVlanInterface, createMultipleVLAN)
{
    createVlan(50);
    createVlan(60);
    config::Parser parser("/tmp/network/test0.50.netdev");
    auto values = parser.getValues("NetDev", "Name");
    std::string expectedValue = "test0.50";
    bool found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("NetDev", "Kind");
    expectedValue = "vlan";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("VLAN", "Id");
    expectedValue = "50";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    parser.setFile("/tmp/network/test0.60.netdev");
    values = parser.getValues("NetDev", "Name");
    expectedValue = "test0.60";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("VLAN", "Id");
    expectedValue = "60";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    deleteVlan("test0.50");
    deleteVlan("test0.60");
}

}// namespce network
}// namespace phosphor
