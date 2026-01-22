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
        return std::make_unique<StaticGateway>(
            bus, "/xyz/openbmc_test/network/test0"sv, interface, gateway,
            protocolType);
    }
};

TEST_F(TestStaticGateway, ConstructorIPv4)
{
    auto gw = createStaticGateway("192.168.1.1", IP::Protocol::IPv4);

    EXPECT_EQ("192.168.1.1", gw->gateway());
    EXPECT_EQ(IP::Protocol::IPv4, gw->protocolType());
}

TEST_F(TestStaticGateway, ConstructorIPv6)
{
    auto gw = createStaticGateway("2001:db8::1", IP::Protocol::IPv6);

    EXPECT_EQ("2001:db8::1", gw->gateway());
    EXPECT_EQ(IP::Protocol::IPv6, gw->protocolType());
}

TEST_F(TestStaticGateway, ConstructorIPv6LinkLocal)
{
    auto gw = createStaticGateway("fe80::1", IP::Protocol::IPv6);

    EXPECT_EQ("fe80::1", gw->gateway());
    EXPECT_EQ(IP::Protocol::IPv6, gw->protocolType());
}

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

TEST_F(TestStaticGateway, DeleteGateway)
{
    std::string gwAddr = "192.168.1.1";
    interface.staticGateways[gwAddr] =
        createStaticGateway(gwAddr, IP::Protocol::IPv4);
    auto* gwPtr = interface.staticGateways[gwAddr].get();

    EXPECT_EQ(1, interface.staticGateways.size());
    EXPECT_CALL(manager.mockReload, schedule());

    gwPtr->delete_();

    EXPECT_EQ(0, interface.staticGateways.size());
}

TEST_F(TestStaticGateway, DeleteTriggersConfigWrite)
{
    std::string gwAddr = "192.168.1.1";
    interface.staticGateways[gwAddr] =
        createStaticGateway(gwAddr, IP::Protocol::IPv4);
    auto* gwPtr = interface.staticGateways[gwAddr].get();

    EXPECT_CALL(manager.mockReload, schedule());
    gwPtr->delete_();
}

TEST_F(TestStaticGateway, MultipleIPv4Gateways)
{
    std::string gw1 = "192.168.1.1";
    std::string gw2 = "192.168.1.254";
    std::string gw3 = "10.0.0.1";

    interface.staticGateways[gw1] =
        createStaticGateway(gw1, IP::Protocol::IPv4);
    interface.staticGateways[gw2] =
        createStaticGateway(gw2, IP::Protocol::IPv4);
    interface.staticGateways[gw3] =
        createStaticGateway(gw3, IP::Protocol::IPv4);

    EXPECT_EQ(3, interface.staticGateways.size());
    EXPECT_EQ("192.168.1.1", interface.staticGateways[gw1]->gateway());
    EXPECT_EQ("192.168.1.254", interface.staticGateways[gw2]->gateway());
    EXPECT_EQ("10.0.0.1", interface.staticGateways[gw3]->gateway());
}

TEST_F(TestStaticGateway, MultipleIPv6Gateways)
{
    std::string gw1 = "2001:db8::1";
    std::string gw2 = "2001:db8::2";
    std::string gw3 = "fe80::1";

    interface.staticGateways[gw1] =
        createStaticGateway(gw1, IP::Protocol::IPv6);
    interface.staticGateways[gw2] =
        createStaticGateway(gw2, IP::Protocol::IPv6);
    interface.staticGateways[gw3] =
        createStaticGateway(gw3, IP::Protocol::IPv6);

    EXPECT_EQ(3, interface.staticGateways.size());
    EXPECT_EQ(IP::Protocol::IPv6,
              interface.staticGateways[gw1]->protocolType());
    EXPECT_EQ(IP::Protocol::IPv6,
              interface.staticGateways[gw2]->protocolType());
    EXPECT_EQ(IP::Protocol::IPv6,
              interface.staticGateways[gw3]->protocolType());
}

TEST_F(TestStaticGateway, MixedProtocolGateways)
{
    std::string gw4 = "192.168.1.1";
    std::string gw6 = "2001:db8::1";

    interface.staticGateways[gw4] =
        createStaticGateway(gw4, IP::Protocol::IPv4);
    interface.staticGateways[gw6] =
        createStaticGateway(gw6, IP::Protocol::IPv6);

    EXPECT_EQ(2, interface.staticGateways.size());
    EXPECT_EQ(IP::Protocol::IPv4,
              interface.staticGateways[gw4]->protocolType());
    EXPECT_EQ(IP::Protocol::IPv6,
              interface.staticGateways[gw6]->protocolType());
}

TEST_F(TestStaticGateway, DeleteMultipleGateways)
{
    std::string gw1 = "192.168.1.1";
    std::string gw2 = "192.168.1.254";

    interface.staticGateways[gw1] =
        createStaticGateway(gw1, IP::Protocol::IPv4);
    interface.staticGateways[gw2] =
        createStaticGateway(gw2, IP::Protocol::IPv4);

    EXPECT_EQ(2, interface.staticGateways.size());

    EXPECT_CALL(manager.mockReload, schedule()).Times(2);

    interface.staticGateways[gw1]->delete_();
    EXPECT_EQ(1, interface.staticGateways.size());

    interface.staticGateways[gw2]->delete_();
    EXPECT_EQ(0, interface.staticGateways.size());
}

TEST_F(TestStaticGateway, IPv4DefaultRoute)
{
    std::string gw = "0.0.0.0";
    auto gateway = createStaticGateway(gw, IP::Protocol::IPv4);

    EXPECT_EQ("0.0.0.0", gateway->gateway());
}

TEST_F(TestStaticGateway, IPv6DefaultRoute)
{
    std::string gw = "::";
    auto gateway = createStaticGateway(gw, IP::Protocol::IPv6);

    EXPECT_EQ("::", gateway->gateway());
}

TEST_F(TestStaticGateway, IPv4PrivateNetwork)
{
    std::string gw = "10.0.0.1";
    auto gateway = createStaticGateway(gw, IP::Protocol::IPv4);

    EXPECT_EQ("10.0.0.1", gateway->gateway());
    EXPECT_EQ(IP::Protocol::IPv4, gateway->protocolType());
}

TEST_F(TestStaticGateway, IPv6UniqueLocal)
{
    std::string gw = "fd00::1";
    auto gateway = createStaticGateway(gw, IP::Protocol::IPv6);

    EXPECT_EQ("fd00::1", gateway->gateway());
    EXPECT_EQ(IP::Protocol::IPv6, gateway->protocolType());
}

TEST_F(TestStaticGateway, IPv4DifferentOctets)
{
    std::vector<std::string> gateways = {"1.2.3.4", "192.168.0.1", "172.16.0.1",
                                         "10.10.10.10"};

    for (const auto& gw : gateways)
    {
        auto gateway = createStaticGateway(gw, IP::Protocol::IPv4);
        EXPECT_EQ(gw, gateway->gateway());
    }
}

TEST_F(TestStaticGateway, IPv6DifferentFormats)
{
    std::vector<std::string> gateways = {"2001:db8::1", "fe80::1",
                                         "2001:db8:0:0:0:0:0:1", "::1"};

    for (const auto& gw : gateways)
    {
        auto gateway = createStaticGateway(gw, IP::Protocol::IPv6);
        EXPECT_EQ(gw, gateway->gateway());
    }
}

TEST_F(TestStaticGateway, DeleteAndReAddGateway)
{
    std::string gwAddr = "192.168.1.1";
    interface.staticGateways[gwAddr] =
        createStaticGateway(gwAddr, IP::Protocol::IPv4);

    EXPECT_EQ(1, interface.staticGateways.size());
    EXPECT_CALL(manager.mockReload, schedule()).Times(1);

    interface.staticGateways[gwAddr]->delete_();
    EXPECT_EQ(0, interface.staticGateways.size());

    interface.staticGateways[gwAddr] =
        createStaticGateway(gwAddr, IP::Protocol::IPv4);
    EXPECT_EQ(1, interface.staticGateways.size());
    EXPECT_EQ("192.168.1.1", interface.staticGateways[gwAddr]->gateway());
}

TEST_F(TestStaticGateway, SameAddressDifferentProtocol)
{
    std::string gw4 = "192.168.1.1";
    std::string gw6 = "2001:db8::1";

    interface.staticGateways[gw4] =
        createStaticGateway(gw4, IP::Protocol::IPv4);
    interface.staticGateways[gw6] =
        createStaticGateway(gw6, IP::Protocol::IPv6);

    EXPECT_EQ(2, interface.staticGateways.size());
    EXPECT_NE(interface.staticGateways[gw4]->protocolType(),
              interface.staticGateways[gw6]->protocolType());
}

TEST_F(TestStaticGateway, ProtocolTypeConsistency)
{
    std::string gw = "192.168.1.1";
    auto gateway = createStaticGateway(gw, IP::Protocol::IPv4);

    EXPECT_EQ(IP::Protocol::IPv4, gateway->protocolType());
    EXPECT_EQ(IP::Protocol::IPv4, gateway->protocolType());
}

TEST_F(TestStaticGateway, MultipleDeletesOnSameInterface)
{
    std::string gw1 = "192.168.1.1";
    std::string gw2 = "10.0.0.1";
    std::string gw3 = "172.16.0.1";

    interface.staticGateways[gw1] =
        createStaticGateway(gw1, IP::Protocol::IPv4);
    interface.staticGateways[gw2] =
        createStaticGateway(gw2, IP::Protocol::IPv4);
    interface.staticGateways[gw3] =
        createStaticGateway(gw3, IP::Protocol::IPv4);

    EXPECT_EQ(3, interface.staticGateways.size());

    EXPECT_CALL(manager.mockReload, schedule()).Times(3);

    interface.staticGateways[gw2]->delete_();
    EXPECT_EQ(2, interface.staticGateways.size());

    interface.staticGateways[gw1]->delete_();
    EXPECT_EQ(1, interface.staticGateways.size());

    interface.staticGateways[gw3]->delete_();
    EXPECT_EQ(0, interface.staticGateways.size());
}

} // namespace network
} // namespace phosphor
