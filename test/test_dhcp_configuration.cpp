#include "config_parser.hpp"
#include "dhcp_configuration.hpp"
#include "mock_ethernet_interface.hpp"
#include "test_network_manager.hpp"

#include <net/if_arp.h>

#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using std::literals::string_view_literals::operator""sv;
using testing::Key;
using testing::UnorderedElementsAre;
using stdplus::operator""_sub;
using json = nlohmann::json;

class TestDHCPConfiguration : public stdplus::gtest::TestWithTmp
{
  public:
    stdplus::Pinned<sdbusplus::bus_t> bus;
    std::filesystem::path confDir;
    TestManager manager;
    MockEthernetInterface interface;
    std::filesystem::path testConfigFile;

    TestDHCPConfiguration() :
        bus(sdbusplus::bus::new_default()), confDir(CaseTmpDir()),
        manager(bus, "/xyz/openbmc_test/network", confDir),
        interface(makeInterface(bus, manager)),
        testConfigFile(confDir / "test_dhcp_config.json")
    {
        // Create default network configuration
        json config;
        config["dhcp"]["allowConfiguration"] = true;
        std::ofstream file(testConfigFile);
        file << config.dump(4);
    }

    static MockEthernetInterface makeInterface(
        stdplus::PinnedRef<sdbusplus::bus_t> bus, TestManager& manager)
    {
        AllIntfInfo info{InterfaceInfo{
            .type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "test0"}};
        return {bus, manager, info, "/xyz/openbmc_test/network",
                config::Parser()};
    }
};

TEST_F(TestDHCPConfiguration, ReadValidConfig)
{
    json config;
    config["dhcp"]["allowConfiguration"] = true;
    std::ofstream file(testConfigFile);
    file << config.dump(4);

    auto parsedConfig = config::parseConfigFile(testConfigFile);
    EXPECT_TRUE(parsedConfig.contains("dhcp"));
    EXPECT_TRUE(parsedConfig["dhcp"].contains("allowConfiguration"));
    EXPECT_TRUE(parsedConfig["dhcp"]["allowConfiguration"].get<bool>());
}

TEST_F(TestDHCPConfiguration, ReadInvalidConfig)
{
    json config;
    config["dhcp"]["allowConfiguration"] = "not_a_boolean";
    std::ofstream file(testConfigFile);
    file << config.dump(4);

    auto parsedConfig = config::parseConfigFile(testConfigFile);
    EXPECT_TRUE(parsedConfig.contains("dhcp"));
    EXPECT_TRUE(parsedConfig["dhcp"].contains("allowConfiguration"));
    EXPECT_FALSE(parsedConfig["dhcp"]["allowConfiguration"].is_boolean());
}

TEST_F(TestDHCPConfiguration, ReadMissingConfig)
{
    std::filesystem::remove(testConfigFile);
    auto parsedConfig = config::parseConfigFile(testConfigFile);
    EXPECT_TRUE(parsedConfig.empty());
}

TEST_F(TestDHCPConfiguration, AllowConfigurationFalse)
{
    json config;
    config["dhcp"]["allowConfiguration"] = false;
    std::ofstream file(testConfigFile);
    file << config.dump(4);

    EXPECT_THROW(interface.dhcpEnabled(DHCPConf::v4), NotAllowed);
    EXPECT_THROW(interface.dhcpEnabled(DHCPConf::v6), NotAllowed);
    EXPECT_THROW(interface.dhcpEnabled(DHCPConf::both), NotAllowed);
    EXPECT_THROW(interface.dhcpEnabled(DHCPConf::v4v6stateless), NotAllowed);
    EXPECT_THROW(interface.dhcpEnabled(DHCPConf::v6stateless), NotAllowed);
}

TEST_F(TestDHCPConfiguration, ConfigFileNotFound)
{
    std::filesystem::remove(testConfigFile);
    EXPECT_NO_THROW(interface.dhcpEnabled(DHCPConf::v4));
    EXPECT_NO_THROW(interface.dhcpEnabled(DHCPConf::v6));
    EXPECT_NO_THROW(interface.dhcpEnabled(DHCPConf::both));
    EXPECT_NO_THROW(interface.dhcpEnabled(DHCPConf::v4v6stateless));
    EXPECT_NO_THROW(interface.dhcpEnabled(DHCPConf::v6stateless));

    // Restore the file
    json config;
    config["dhcp"]["allowConfiguration"] = true;
    std::ofstream file(testConfigFile);
    file << config.dump(4);
}

} // namespace network
} // namespace phosphor
