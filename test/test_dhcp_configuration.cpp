#include "config_parser.hpp"
#include "dhcp_configuration.hpp"
#include "mock_ethernet_interface.hpp"
#include "test_network_manager.hpp"

#include <net/if_arp.h>

#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>

#include <filesystem>
#include <fstream>
#include <string_view>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{
namespace dhcp
{

using std::literals::string_view_literals::operator""sv;
using testing::Return;

class TestDHCPConfiguration : public stdplus::gtest::TestWithTmp
{
  public:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    std::filesystem::path confDir;
    TestManager manager;
    MockEthernetInterface interface;
    static inline int testCounter = 0;
    int currentTestId;

    TestDHCPConfiguration() :
        bus(sdbusplus::bus::new_default()), confDir(CaseTmpDir()),
        manager(bus, "/xyz/openbmc_test/network", confDir),
        interface(makeInterface(bus, manager)), currentTestId(testCounter++)
    {}

    static MockEthernetInterface makeInterface(
        stdplus::PinnedRef<sdbusplus::bus_t> bus, TestManager& manager)
    {
        AllIntfInfo info{InterfaceInfo{
            .type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "test0"}};
        return {bus, manager, info, "/xyz/openbmc_test/network"sv,
                config::Parser()};
    }

    void writeConfigFile(const std::string& content)
    {
        auto confPath = confDir / "00-bmc-test0.network";
        std::ofstream file(confPath);
        file << content;
        file.close();
    }

    std::unique_ptr<Configuration> createDHCPv4Config()
    {
        EthernetInterface& ethIntf = interface;
        return std::make_unique<Configuration>(
            bus,
            "/xyz/openbmc_test/network/test0/dhcp4_" +
                std::to_string(currentTestId),
            ethIntf, DHCPType::v4);
    }

    std::unique_ptr<Configuration> createDHCPv6Config()
    {
        EthernetInterface& ethIntf = interface;
        return std::make_unique<Configuration>(
            bus,
            "/xyz/openbmc_test/network/test0/dhcp6_" +
                std::to_string(currentTestId),
            ethIntf, DHCPType::v6);
    }
};

TEST_F(TestDHCPConfiguration, ConstructorDHCPv4DefaultValues)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, ConstructorDHCPv4LoadFromConfig)
{
    writeConfigFile(R"([Network]
DHCP=ipv4
[DHCPv4]
UseDNS=true
UseNTP=true
UseHostname=true
SendHostname=true
UseDomains=true
)");

    auto dhcp = createDHCPv4Config();

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, ConstructorDHCPv6DefaultValues)
{
    auto dhcp = createDHCPv6Config();

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, ConstructorDHCPv6LoadFromConfig)
{
    writeConfigFile(R"([Network]
DHCP=ipv6
[DHCPv6]
UseDNS=true
UseNTP=false
UseHostname=true
SendHostname=false
UseDomains=true
)");

    auto dhcp = createDHCPv6Config();

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_FALSE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_FALSE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, SetDNSEnabledTrue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->dnsEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->dnsEnabled(true));
    EXPECT_TRUE(dhcp->dnsEnabled());
}

TEST_F(TestDHCPConfiguration, SetDNSEnabledFalse)
{
    writeConfigFile(R"([DHCPv4]
UseDNS=true
)");
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->dnsEnabled());

    EXPECT_CALL(manager.mockReload, schedule());
    EXPECT_FALSE(dhcp->dnsEnabled(false));
    EXPECT_FALSE(dhcp->dnsEnabled());
}

TEST_F(TestDHCPConfiguration, SetDNSEnabledNoOpSameValue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->dnsEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->dnsEnabled(true));
}

TEST_F(TestDHCPConfiguration, SetNTPEnabledTrue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->ntpEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->ntpEnabled(true));
    EXPECT_TRUE(dhcp->ntpEnabled());
}

TEST_F(TestDHCPConfiguration, SetNTPEnabledFalse)
{
    writeConfigFile(R"([DHCPv4]
UseNTP=true
)");
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->ntpEnabled());

    EXPECT_CALL(manager.mockReload, schedule());
    EXPECT_FALSE(dhcp->ntpEnabled(false));
    EXPECT_FALSE(dhcp->ntpEnabled());
}

TEST_F(TestDHCPConfiguration, SetNTPEnabledNoOpSameValue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->ntpEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->ntpEnabled(true));
}

TEST_F(TestDHCPConfiguration, SetHostNameEnabledTrue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->hostNameEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->hostNameEnabled(true));
    EXPECT_TRUE(dhcp->hostNameEnabled());
}

TEST_F(TestDHCPConfiguration, SetHostNameEnabledFalse)
{
    writeConfigFile(R"([DHCPv4]
UseHostname=true
)");
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->hostNameEnabled());

    EXPECT_CALL(manager.mockReload, schedule());
    EXPECT_FALSE(dhcp->hostNameEnabled(false));
    EXPECT_FALSE(dhcp->hostNameEnabled());
}

TEST_F(TestDHCPConfiguration, SetHostNameEnabledNoOpSameValue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->hostNameEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->hostNameEnabled(true));
}

TEST_F(TestDHCPConfiguration, SetSendHostNameEnabledTrue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->sendHostNameEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->sendHostNameEnabled(true));
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
}

TEST_F(TestDHCPConfiguration, SetSendHostNameEnabledFalse)
{
    writeConfigFile(R"([DHCPv4]
SendHostname=true
)");
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->sendHostNameEnabled());

    EXPECT_CALL(manager.mockReload, schedule());
    EXPECT_FALSE(dhcp->sendHostNameEnabled(false));
    EXPECT_FALSE(dhcp->sendHostNameEnabled());
}

TEST_F(TestDHCPConfiguration, SetSendHostNameEnabledNoOpSameValue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->sendHostNameEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->sendHostNameEnabled(true));
}

TEST_F(TestDHCPConfiguration, SetDomainEnabledTrue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->domainEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->domainEnabled(true));
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, SetDomainEnabledFalse)
{
    writeConfigFile(R"([DHCPv4]
UseDomains=true
)");
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->domainEnabled());

    EXPECT_CALL(manager.mockReload, schedule());
    EXPECT_FALSE(dhcp->domainEnabled(false));
    EXPECT_FALSE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, SetDomainEnabledNoOpSameValue)
{
    auto dhcp = createDHCPv4Config();
    EXPECT_TRUE(dhcp->domainEnabled());

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);
    EXPECT_TRUE(dhcp->domainEnabled(true));
}

TEST_F(TestDHCPConfiguration, SetMultiplePropertiesSequentially)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);

    dhcp->dnsEnabled(true);
    dhcp->ntpEnabled(true);
    dhcp->hostNameEnabled(true);
    dhcp->sendHostNameEnabled(true);
    dhcp->domainEnabled(true);

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, TogglePropertiesMultipleTimes)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(3);

    dhcp->dnsEnabled(false);
    EXPECT_FALSE(dhcp->dnsEnabled());

    dhcp->dnsEnabled(true);
    EXPECT_TRUE(dhcp->dnsEnabled());

    dhcp->dnsEnabled(false);
    EXPECT_FALSE(dhcp->dnsEnabled());
}

TEST_F(TestDHCPConfiguration, DHCPv6AllPropertiesEnabled)
{
    auto dhcp = createDHCPv6Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);

    dhcp->dnsEnabled(true);
    dhcp->ntpEnabled(true);
    dhcp->hostNameEnabled(true);
    dhcp->sendHostNameEnabled(true);
    dhcp->domainEnabled(true);

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, PartialConfigurationEnabled)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(2);

    dhcp->dnsEnabled(true);
    dhcp->ntpEnabled(true);
    dhcp->hostNameEnabled(false);
    dhcp->sendHostNameEnabled(false);
    dhcp->domainEnabled(true);

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_FALSE(dhcp->hostNameEnabled());
    EXPECT_FALSE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, ConfigWrittenAfterUpdate)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule());
    dhcp->dnsEnabled(false);

    auto confPath = confDir / "00-bmc-test0.network";
    EXPECT_TRUE(std::filesystem::exists(confPath));
}

TEST_F(TestDHCPConfiguration, RapidPropertyChanges)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(10);

    for (int i = 0; i < 5; ++i)
    {
        dhcp->dnsEnabled(false);
        dhcp->dnsEnabled(true);
    }
}

TEST_F(TestDHCPConfiguration, AllPropertiesDisabled)
{
    writeConfigFile(R"([DHCPv4]
UseDNS=true
UseNTP=true
UseHostname=true
SendHostname=true
UseDomains=true
)");

    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(5);

    dhcp->dnsEnabled(false);
    dhcp->ntpEnabled(false);
    dhcp->hostNameEnabled(false);
    dhcp->sendHostNameEnabled(false);
    dhcp->domainEnabled(false);

    EXPECT_FALSE(dhcp->dnsEnabled());
    EXPECT_FALSE(dhcp->ntpEnabled());
    EXPECT_FALSE(dhcp->hostNameEnabled());
    EXPECT_FALSE(dhcp->sendHostNameEnabled());
    EXPECT_FALSE(dhcp->domainEnabled());
}

TEST_F(TestDHCPConfiguration, PropertiesAreIndependent)
{
    auto dhcp = createDHCPv4Config();

    EXPECT_CALL(manager.mockReload, schedule()).Times(0);

    dhcp->dnsEnabled(true);
    dhcp->ntpEnabled(true);

    EXPECT_TRUE(dhcp->dnsEnabled());
    EXPECT_TRUE(dhcp->ntpEnabled());
    EXPECT_TRUE(dhcp->hostNameEnabled());
    EXPECT_TRUE(dhcp->sendHostNameEnabled());
    EXPECT_TRUE(dhcp->domainEnabled());
}

} // namespace dhcp
} // namespace network
} // namespace phosphor
