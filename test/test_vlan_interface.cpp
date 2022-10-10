#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"
#include "system_queries.hpp"
#include "vlan_interface.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <filesystem>
#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

namespace fs = std::filesystem;
using std::literals::string_view_literals::operator""sv;

class TestVlanInterface : public stdplus::gtest::TestWithTmp
{
  public:
    sdbusplus::bus_t bus;
    std::string confDir;
    MockManager manager;
    EthernetInterface interface;
    TestVlanInterface() :
        bus(sdbusplus::bus::new_default()), confDir(CaseTmpDir()),
        manager(bus, "/xyz/openbmc_test/network", confDir),
        interface(makeInterface(bus, manager))

    {
    }

    static EthernetInterface makeInterface(sdbusplus::bus_t& bus,
                                           MockManager& manager)
    {
        mock_clear();
        mock_addIF("test0", /*idx=*/1);
        return {bus,
                manager,
                system::InterfaceInfo{.idx = 1, .flags = 0, .name = "test0"},
                "/xyz/openbmc_test/network"sv,
                config::Parser(),
                /*emitSignal=*/false,
                /*nicEnabled=*/true};
    }

    void createVlan(uint16_t id)
    {
        std::string ifname = "test0.";
        ifname += std::to_string(id);
        mock_addIF(ifname.c_str(), 1000 + id);
        interface.createVLAN(id);
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

    void createIPObject(IP::Protocol addressType, const std::string& ipaddress,
                        uint8_t subnetMask, const std::string& gateway)
    {
        interface.ip(addressType, ipaddress, subnetMask, gateway);
    }
};

TEST_F(TestVlanInterface, createVLAN)
{
    createVlan(50);
    fs::path filePath = confDir;
    filePath /= "test0.50.netdev";

    config::Parser parser(filePath);
    EXPECT_EQ(parser.map, config::SectionMap(config::SectionMapInt{
                              {"NetDev",
                               {
                                   {{"Name", {"test0.50"}}, {"Kind", {"vlan"}}},
                               }},
                              {"VLAN", {{{"Id", {"50"}}}}},
                          }));
}

TEST_F(TestVlanInterface, deleteVLAN)
{
    createVlan(50);
    deleteVlan("test0.50");

    fs::path filePath = confDir;
    filePath /= "test0.50.netdev";
    EXPECT_FALSE(fs::is_regular_file(filePath));
}

TEST_F(TestVlanInterface, createMultipleVLAN)
{
    createVlan(50);
    createVlan(60);

    fs::path filePath = confDir;
    filePath /= "test0.50.netdev";
    config::Parser parser(filePath);
    EXPECT_EQ(parser.map, config::SectionMap(config::SectionMapInt{
                              {"NetDev",
                               {
                                   {{"Name", {"test0.50"}}, {"Kind", {"vlan"}}},
                               }},
                              {"VLAN", {{{"Id", {"50"}}}}},
                          }));

    filePath = confDir;
    filePath /= "test0.60.netdev";
    parser.setFile(filePath);
    EXPECT_EQ(parser.map, config::SectionMap(config::SectionMapInt{
                              {"NetDev",
                               {
                                   {{"Name", {"test0.60"}}, {"Kind", {"vlan"}}},
                               }},
                              {"VLAN", {{{"Id", {"60"}}}}},
                          }));

    deleteVlan("test0.50");
    deleteVlan("test0.60");
}

} // namespace network
} // namespace phosphor
