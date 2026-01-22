#include "config_parser.hpp"
#include "mock_ethernet_interface.hpp"
#include "static_gateway.hpp"
#include "test_network_manager.hpp"

#include <net/if_arp.h>

#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <string_view>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using std::literals::string_view_literals::operator""sv;
using testing::Return;

class TestStaticGateway : public stdplus::gtest::TestWithTmp
{
  public:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    std::filesystem::path confDir;
    TestManager manager;
    MockEthernetInterface interface;

    TestStaticGateway() :
        bus(sdbusplus::bus::new_default()), confDir(CaseTmpDir()),
        manager(bus, "/xyz/openbmc_test/network", confDir),
        interface(makeInterface(bus, manager))
    {}

    static MockEthernetInterface makeInterface(
        stdplus::PinnedRef<sdbusplus::bus_t> bus, TestManager& manager)
    {
        AllIntfInfo info{InterfaceInfo{
            .type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "test0"}};
        return {bus, manager, info, "/xyz/openbmc_test/network"sv,
                config::Parser()};
    }

    std::unique_ptr<StaticGateway> createStaticGateway(
        std::string gateway, IP::Protocol protocolType)
    {
        auto pinnedIface = stdplus::Pinned<MockEthernetInterface>(interface);

        return std::make_unique<phosphor::network::StaticGateway>(
            stdplus::PinnedRef<EthernetInterface>(pinnedIface), gateway,
            protocol);
    }

};

TEST_F(TestStaticGateway, SetGatewayNotAllowed)
{
    auto gw = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);

    EXPECT_THROW(gw->gateway("192.168.1.254"), NotAllowed);
    EXPECT_EQ("192.168.1.1", gw->gateway());
}

TEST_F(TestStaticGateway, SetProtocolTypeNotAllowed)
{
    auto gw = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);

    EXPECT_THROW(gw->protocolType(IP::Protocol::IPv6), NotAllowed);
    EXPECT_EQ(IP::Protocol::IPv4, gw->protocolType());
}

TEST_F(TestStaticGateway, GetGatewayIPv4)
{
    auto gw = createStaticGateway("10.0.0.1", IP::Protocol::IPv4);
    EXPECT_EQ("10.0.0.1", gw->gateway());
}

TEST_F(TestStaticGateway, GetGatewayIPv6)
{
    auto gw = createStaticGateway("fd00::1", IP::Protocol::IPv6);
    EXPECT_EQ("fd00::1", gw->gateway());
}

TEST_F(TestStaticGateway, GetProtocolTypeIPv4)
{
    auto gw = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);
    EXPECT_EQ(IP::Protocol::IPv4, gw->protocolType());
}

TEST_F(TestStaticGateway, GetProtocolTypeIPv6)
{
    auto gw = createStaticGateway("2001:db8::1", IP::Protocol::IPv6);
    EXPECT_EQ(IP::Protocol::IPv6, gw->protocolType());
}

TEST_F(TestStaticGateway, DeleteGateway)
{
    auto gw = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);
    EXPECT_NO_THROW(gw->delete_());
}

TEST_F(TestStaticGateway, DeleteIPv6Gateway)
{
    auto gw = createStaticGateway("2001:db8::1", IP::Protocol::IPv6);
    EXPECT_NO_THROW(gw->delete_());
}

TEST_F(TestStaticGateway, IPv4DefaultRoute)
{
    auto gateway = createStaticGateway("0.0.0.0", IP::Protocol::IPv4);
    EXPECT_EQ("0.0.0.0", gateway->gateway());
}

TEST_F(TestStaticGateway, IPv6DefaultRoute)
{
    auto gateway = createStaticGateway("::", IP::Protocol::IPv6);
    EXPECT_EQ("::", gateway->gateway());
}

TEST_F(TestStaticGateway, IPv4PrivateNetwork)
{
    auto gateway = createStaticGateway("10.0.0.1", IP::Protocol::IPv4);
    EXPECT_EQ("10.0.0.1", gateway->gateway());
    EXPECT_EQ(IP::Protocol::IPv4, gateway->protocolType());
}

TEST_F(TestStaticGateway, IPv6UniqueLocal)
{
    auto gateway = createStaticGateway("fd00::1", IP::Protocol::IPv6);
    EXPECT_EQ("fd00::1", gateway->gateway());
    EXPECT_EQ(IP::Protocol::IPv6, gateway->protocolType());
}

TEST_F(TestStaticGateway, IPv4DifferentOctets)
{
    std::vector<std::string> gateways = {"192.168.1.1", "10.0.0.1",
                                         "172.16.0.1", "1.2.3.4"};

    for (const auto& gw : gateways)
    {
        auto gateway = createStaticGateway(gw, IP::Protocol::IPv4);
        EXPECT_EQ(gw, gateway->gateway());
    }
}

TEST_F(TestStaticGateway, IPv6DifferentFormats)
{
    std::vector<std::string> gateways = {
        "2001:db8::1", "fe80::1", "::1",
        "2001:0db8:0000:0000:0000:0000:0000:0001"};

    for (const auto& gw : gateways)
    {
        auto gateway = createStaticGateway(gw, IP::Protocol::IPv6);
        EXPECT_EQ(gw, gateway->gateway());
    }
}

TEST_F(TestStaticGateway, MultipleIPv4Gateways)
{
    auto gw1 = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);
    auto gw2 = createStaticGateway("192.168.1.254", IP::Protocol::IPv4);
    auto gw3 = createStaticGateway("10.0.0.1", IP::Protocol::IPv4);

    EXPECT_EQ("192.168.1.1", gw1->gateway());
    EXPECT_EQ("192.168.1.254", gw2->gateway());
    EXPECT_EQ("10.0.0.1", gw3->gateway());
}

TEST_F(TestStaticGateway, MultipleIPv6Gateways)
{
    auto gw1 = createStaticGateway("2001:db8::1", IP::Protocol::IPv6);
    auto gw2 = createStaticGateway("fe80::1", IP::Protocol::IPv6);
    auto gw3 = createStaticGateway("fd00::1", IP::Protocol::IPv6);

    EXPECT_EQ("2001:db8::1", gw1->gateway());
    EXPECT_EQ("fe80::1", gw2->gateway());
    EXPECT_EQ("fd00::1", gw3->gateway());
}

TEST_F(TestStaticGateway, MixedProtocolGateways)
{
    auto gw4 = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);
    auto gw6 = createStaticGateway("2001:db8::1", IP::Protocol::IPv6);

    EXPECT_EQ("192.168.1.1", gw4->gateway());
    EXPECT_EQ(IP::Protocol::IPv4, gw4->protocolType());

    EXPECT_EQ("2001:db8::1", gw6->gateway());
    EXPECT_EQ(IP::Protocol::IPv6, gw6->protocolType());
}

TEST_F(TestStaticGateway, DeleteMultipleGateways)
{
    auto gw1 = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);
    auto gw2 = createStaticGateway("192.168.1.254", IP::Protocol::IPv4);
    auto gw3 = createStaticGateway("10.0.0.1", IP::Protocol::IPv4);

    EXPECT_NO_THROW(gw1->delete_());
    EXPECT_NO_THROW(gw2->delete_());
    EXPECT_NO_THROW(gw3->delete_());
}

TEST_F(TestStaticGateway, DeleteAndReAddGateway)
{
    std::string gwAddr = "192.168.1.1";

    auto gw1 = createStaticGateway(gwAddr, IP::Protocol::IPv4);
    EXPECT_EQ(gwAddr, gw1->gateway());
    EXPECT_NO_THROW(gw1->delete_());

    auto gw2 = createStaticGateway(gwAddr, IP::Protocol::IPv4);
    EXPECT_EQ(gwAddr, gw2->gateway());
}

TEST_F(TestStaticGateway, SameAddressDifferentProtocol)
{
    std::string gw4 = "1.2.3.4";
    std::string gw6 = "2001:db8::1";

    auto gateway4 = createStaticGateway(gw4, IP::Protocol::IPv4);
    auto gateway6 = createStaticGateway(gw6, IP::Protocol::IPv6);

    EXPECT_EQ(IP::Protocol::IPv4, gateway4->protocolType());
    EXPECT_EQ(IP::Protocol::IPv6, gateway6->protocolType());
}

TEST_F(TestStaticGateway, ProtocolTypeConsistency)
{
    auto gateway = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);

    EXPECT_EQ(IP::Protocol::IPv4, gateway->protocolType());
    EXPECT_EQ(IP::Protocol::IPv4, gateway->protocolType());
}

TEST_F(TestStaticGateway, MultipleDeletesOnSameInterface)
{
    auto gw1 = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);
    auto gw2 = createStaticGateway("192.168.1.254", IP::Protocol::IPv4);
    auto gw3 = createStaticGateway("10.0.0.1", IP::Protocol::IPv4);

    EXPECT_NO_THROW(gw2->delete_());
    EXPECT_NO_THROW(gw1->delete_());
    EXPECT_NO_THROW(gw3->delete_());
}

} // namespace network
} // namespace phosphor
