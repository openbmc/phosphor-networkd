#include "config_parser.hpp"
#include "dhcp_configuration.hpp"
#include "mock_ethernet_interface.hpp"
#include "test_network_manager.hpp"

#include <nlohmann/json.hpp>
#include <sdbusplus/bus.hpp>
#include <stdplus/gtest/tmp.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <fstream>

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
    std::filesystem::path testConfigFile;

    TestDHCPConfiguration() :
        testConfigFile(
            std::filesystem::path(CaseTmpDir()) / "test_dhcp_config.json")
    {
        // Create default network configuration
        json config;
        config["dhcp"]["allowConfiguration"] = true;
        std::ofstream file(testConfigFile);
        file << config.dump(4);
        file.close();
    }
};

TEST_F(TestDHCPConfiguration, ReadValidConfig)
{
    json config;
    config["dhcp"]["allowConfiguration"] = true;
    std::ofstream file(testConfigFile);
    file << config.dump(4);
    file.close();

    auto parsedConfig = config::parseConfigFile(testConfigFile);
    ASSERT_FALSE(parsedConfig.empty());
    ASSERT_TRUE(parsedConfig.contains("dhcp"));
    ASSERT_TRUE(parsedConfig["dhcp"].contains("allowConfiguration"));
    EXPECT_TRUE(parsedConfig["dhcp"]["allowConfiguration"].get<bool>());
}

TEST_F(TestDHCPConfiguration, ReadInvalidConfig)
{
    json config;
    config["dhcp"]["allowConfiguration"] = "not_a_boolean";
    std::ofstream file(testConfigFile);
    file << config.dump(4);
    file.close();

    auto parsedConfig = config::parseConfigFile(testConfigFile);
    ASSERT_FALSE(parsedConfig.empty());
    ASSERT_TRUE(parsedConfig.contains("dhcp"));
    ASSERT_TRUE(parsedConfig["dhcp"].contains("allowConfiguration"));
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
    file.close();

    auto parsedConfig = config::parseConfigFile(testConfigFile);
    ASSERT_FALSE(parsedConfig.empty());
    ASSERT_TRUE(parsedConfig.contains("dhcp"));
    ASSERT_TRUE(parsedConfig["dhcp"].contains("allowConfiguration"));
    EXPECT_FALSE(parsedConfig["dhcp"]["allowConfiguration"].get<bool>());
}

TEST_F(TestDHCPConfiguration, ConfigFileNotFound)
{
    std::filesystem::remove(testConfigFile);
    auto parsedConfig = config::parseConfigFile(testConfigFile);
    EXPECT_TRUE(parsedConfig.empty());

    // Restore the file
    json config;
    config["dhcp"]["allowConfiguration"] = true;
    std::ofstream file(testConfigFile);
    file << config.dump(4);
    file.close();
}

} // namespace network
} // namespace phosphor
