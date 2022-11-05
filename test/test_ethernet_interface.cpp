#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"
#include "system_queries.hpp"
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using std::literals::string_view_literals::operator""sv;
using testing::Key;
using testing::UnorderedElementsAre;

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
        system::mock_clear();
        system::InterfaceInfo info{.idx = 1, .flags = 0, .name = "test0"};
        system::mock_addIF(info);
        return {bus, manager, info, "/xyz/openbmc_test/network"sv,
                config::Parser()};
    }

    auto createIPObject(IP::Protocol addressType, const std::string& ipaddress,
                        uint8_t subnetMask)
    {
        return interface.ip(addressType, ipaddress, subnetMask, "");
    }

    void setNtpServers()
    {
        ServerList ntpServers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
        interface.EthernetInterfaceIntf::ntpServers(ntpServers);
    }

    ServerList getNtpServers()
    {
        return interface.EthernetInterfaceIntf::ntpServers();
    }
};

TEST_F(TestEthernetInterface, Fields)
{
    EXPECT_EQ(0, interface.mtu());
    EXPECT_EQ("", interface.macAddress());
    EXPECT_FALSE(interface.linkUp());

    constexpr ether_addr mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    constexpr unsigned mtu = 150;

    system::InterfaceInfo info{.idx = 2,
                               .flags = IFF_RUNNING,
                               .name = "test1",
                               .mac = mac,
                               .mtu = mtu};
    system::mock_addIF(info);
    MockEthernetInterface intf(bus, manager, info,
                               "/xyz/openbmc_test/network"sv, config::Parser());

    EXPECT_EQ(mtu, intf.mtu());
    EXPECT_EQ(std::to_string(mac), intf.macAddress());
    EXPECT_TRUE(intf.linkUp());
}

TEST_F(TestEthernetInterface, NoIPaddress)
{
    EXPECT_TRUE(interface.addrs.empty());
}

TEST_F(TestEthernetInterface, AddIPAddress)
{
    createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    EXPECT_THAT(interface.addrs, UnorderedElementsAre(Key(
                                     IfAddr(in_addr{htonl(0x0a0a0a0a)}, 16))));
}

TEST_F(TestEthernetInterface, AddMultipleAddress)
{
    createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    createIPObject(IP::Protocol::IPv4, "20.20.20.20", 16);
    EXPECT_THAT(
        interface.addrs,
        UnorderedElementsAre(Key(IfAddr(in_addr{htonl(0x0a0a0a0a)}, 16)),
                             Key(IfAddr(in_addr{htonl(0x14141414)}, 16))));
}

TEST_F(TestEthernetInterface, DeleteIPAddress)
{
    createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    createIPObject(IP::Protocol::IPv4, "20.20.20.20", 16);
    interface.addrs.at(IfAddr(in_addr{htonl(0x0a0a0a0a)}, 16))->delete_();
    EXPECT_THAT(interface.addrs, UnorderedElementsAre(Key(
                                     IfAddr(in_addr{htonl(0x14141414)}, 16))));
}

TEST_F(TestEthernetInterface, CheckObjectPath)
{
    auto path = createIPObject(IP::Protocol::IPv4, "10.10.10.10", 16);
    EXPECT_EQ(path.parent_path(), "/xyz/openbmc_test/network/test0");
    EXPECT_EQ(path.filename(), "10.10.10.10/16");
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
    setNtpServers();
    EXPECT_EQ(getNtpServers(), servers);
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
