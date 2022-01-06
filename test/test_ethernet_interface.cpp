#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <charconv>
#include <exception>
#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using std::literals::string_view_literals::operator""sv;

class TestEthernetInterface : public stdplus::gtest::TestWithTmp
{
  public:
    sdbusplus::bus_t bus;
    std::string confDir;
    MockManager manager;
    MockEthernetInterface interface;
    TestEthernetInterface() :
        bus(sdbusplus::bus::new_default()), confDir(CaseTmpDir()),
        manager(bus, "/xyz/openbmc_test/network", confDir),
        interface(makeInterface(bus, manager))

    {
    }

    static MockEthernetInterface makeInterface(sdbusplus::bus_t& bus,
                                               MockManager& manager)
    {
        mock_clear();
        mock_addIF("test0", /*idx=*/1);
        return {bus, "/xyz/openbmc_test/network/test0", config::Parser(),
                manager};
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

    std::string getObjectPath(const std::string& ipaddress, uint8_t subnetMask,
                              IP::AddressOrigin origin)
    {
        IP::Protocol addressType = IP::Protocol::IPv4;

        return interface.generateObjectPath(addressType, ipaddress, subnetMask,
                                            origin);
    }

    void createIPObject(IP::Protocol addressType, const std::string& ipaddress,
                        uint8_t subnetMask)
    {
        interface.ip(addressType, ipaddress, subnetMask, "");
    }

    void setNTPServers()
    {
        ServerList ntpServers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
        interface.EthernetInterfaceIntf::ntpServers(ntpServers);
    }
};

TEST_F(TestEthernetInterface, Fields)
{
    EXPECT_EQ(0, interface.mtu());
    EXPECT_EQ("", interface.macAddress());
    EXPECT_FALSE(interface.linkUp());

    constexpr unsigned idx = 2;
    constexpr ether_addr mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    constexpr unsigned mtu = 150;

    mock_addIF("test1", idx, IFF_RUNNING, mac, mtu);
    MockEthernetInterface intf(bus, "/xyz/openbmc_test/network/test1",
                               config::Parser(), manager);

    EXPECT_EQ(mtu, intf.mtu());
    EXPECT_EQ(mac_address::toString(mac), intf.macAddress());
    EXPECT_TRUE(intf.linkUp());
}

TEST_F(TestEthernetInterface, NoIPaddress)
{
    EXPECT_EQ(countIPObjects(), 0);
}

TEST_F(TestEthernetInterface, AddIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16);
    EXPECT_EQ(true, isIPObjectExist("10.10.10.10"));
}

TEST_F(TestEthernetInterface, AddMultipleAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16);
    createIPObject(addressType, "20.20.20.20", 16);
    EXPECT_EQ(true, isIPObjectExist("10.10.10.10"));
    EXPECT_EQ(true, isIPObjectExist("20.20.20.20"));
}

TEST_F(TestEthernetInterface, DeleteIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16);
    createIPObject(addressType, "20.20.20.20", 16);
    deleteIPObject("10.10.10.10");
    EXPECT_EQ(false, isIPObjectExist("10.10.10.10"));
    EXPECT_EQ(true, isIPObjectExist("20.20.20.20"));
}

TEST_F(TestEthernetInterface, DeleteInvalidIPAddress)
{
    EXPECT_EQ(false, deleteIPObject("10.10.10.10"));
}

TEST_F(TestEthernetInterface, CheckObjectPath)
{
    std::string ipaddress = "10.10.10.10";
    uint8_t prefix = 16;
    IP::AddressOrigin origin = IP::AddressOrigin::Static;

    auto path = getObjectPath(ipaddress, prefix, origin);
    auto pathsv = std::string_view(path);
    constexpr auto expectedPrefix = "/xyz/openbmc_test/network/test0/ipv4/"sv;
    EXPECT_TRUE(pathsv.starts_with(expectedPrefix));
    pathsv.remove_prefix(expectedPrefix.size());
    uint32_t val;
    auto [ptr, res] = std::from_chars(pathsv.begin(), pathsv.end(), val, 16);
    EXPECT_EQ(res, std::errc());
    EXPECT_EQ(ptr, pathsv.end());

    EXPECT_EQ(path, getObjectPath(ipaddress, prefix, origin));
    origin = IP::AddressOrigin::DHCP;
    EXPECT_NE(path, getObjectPath(ipaddress, prefix, origin));
}

TEST_F(TestEthernetInterface, addStaticNameServers)
{
    ServerList servers = {"9.1.1.1", "9.2.2.2", "9.3.3.3"};
    EXPECT_CALL(manager, reloadConfigs());
    interface.staticNameServers(servers);
    fs::path filePath = confDir;
    filePath /= "00-bmc-test0.network";
    config::Parser parser(filePath.string());
    EXPECT_EQ(servers, parser.map.getValueStrings("Network", "DNS"));
}

TEST_F(TestEthernetInterface, getDynamicNameServers)
{
    ServerList servers = {"9.1.1.1", "9.2.2.2", "9.3.3.3"};
    EXPECT_CALL(interface, getNameServerFromResolvd())
        .WillRepeatedly(testing::Return(servers));
    EXPECT_EQ(interface.getNameServerFromResolvd(), servers);
}

TEST_F(TestEthernetInterface, addStaticNTPServers)
{
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    EXPECT_CALL(manager, reloadConfigs());
    interface.staticNTPServers(servers);
    fs::path filePath = confDir;
    filePath /= "00-bmc-test0.network";
    config::Parser parser(filePath.string());
    EXPECT_EQ(servers, parser.map.getValueStrings("Network", "NTP"));
}

TEST_F(TestEthernetInterface, addNTPServers)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    EXPECT_THROW(interface.ntpServers(servers), NotAllowed);
}

TEST_F(TestEthernetInterface, getNTPServers)
{
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    setNTPServers();
    EXPECT_EQ(interface.getNtpServers(), servers);
}

TEST_F(TestEthernetInterface, addGateway)
{
    std::string gateway = "10.3.3.3";
    interface.defaultGateway(gateway);
    EXPECT_EQ(interface.defaultGateway(), gateway);
    interface.defaultGateway("");
    EXPECT_EQ(interface.defaultGateway(), "");
}

TEST_F(TestEthernetInterface, addGateway6)
{
    std::string gateway6 = "ffff:ffff:ffff:fe80::1";
    interface.defaultGateway6(gateway6);
    EXPECT_EQ(interface.defaultGateway6(), gateway6);
    interface.defaultGateway6("");
    EXPECT_EQ(interface.defaultGateway6(), "");
}

TEST_F(TestEthernetInterface, DHCPEnabled)
{
    EXPECT_CALL(manager, reloadConfigs()).WillRepeatedly(testing::Return());

    using DHCPConf = EthernetInterfaceIntf::DHCPConf;
    auto test = [&](DHCPConf conf, bool dhcp4, bool dhcp6, bool ra) {
        EXPECT_EQ(conf, interface.dhcpEnabled());
        EXPECT_EQ(dhcp4, interface.dhcp4());
        EXPECT_EQ(dhcp6, interface.dhcp6());
        EXPECT_EQ(ra, interface.ipv6AcceptRA());
    };
    test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/true);

    auto set_test = [&](DHCPConf conf, bool dhcp4, bool dhcp6, bool ra) {
        EXPECT_EQ(conf, interface.dhcpEnabled(conf));
        test(conf, dhcp4, dhcp6, ra);
    };
    set_test(DHCPConf::none, /*dhcp4=*/false, /*dhcp6=*/false, /*ra=*/false);
    set_test(DHCPConf::v4, /*dhcp4=*/true, /*dhcp6=*/false, /*ra=*/false);
    set_test(DHCPConf::v6stateless, /*dhcp4=*/false, /*dhcp6=*/false,
             /*ra=*/true);
    set_test(DHCPConf::v6, /*dhcp4=*/false, /*dhcp6=*/true, /*ra=*/true);
    set_test(DHCPConf::v4v6stateless, /*dhcp4=*/true, /*dhcp6=*/false,
             /*ra=*/true);
    set_test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/true);

    auto ind_test = [&](DHCPConf conf, bool dhcp4, bool dhcp6, bool ra) {
        EXPECT_EQ(dhcp4, interface.dhcp4(dhcp4));
        EXPECT_EQ(dhcp6, interface.dhcp6(dhcp6));
        EXPECT_EQ(ra, interface.ipv6AcceptRA(ra));
        test(conf, dhcp4, dhcp6, ra);
    };
    ind_test(DHCPConf::none, /*dhcp4=*/false, /*dhcp6=*/false, /*ra=*/false);
    ind_test(DHCPConf::v4, /*dhcp4=*/true, /*dhcp6=*/false, /*ra=*/false);
    ind_test(DHCPConf::v6stateless, /*dhcp4=*/false, /*dhcp6=*/false,
             /*ra=*/true);
    ind_test(DHCPConf::v6, /*dhcp4=*/false, /*dhcp6=*/true, /*ra=*/false);
    set_test(DHCPConf::v6, /*dhcp4=*/false, /*dhcp6=*/true, /*ra=*/true);
    ind_test(DHCPConf::v4v6stateless, /*dhcp4=*/true, /*dhcp6=*/false,
             /*ra=*/true);
    ind_test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/false);
    set_test(DHCPConf::both, /*dhcp4=*/true, /*dhcp6=*/true, /*ra=*/true);
}

} // namespace network
} // namespace phosphor
