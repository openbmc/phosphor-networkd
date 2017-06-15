#include <gtest/gtest.h>

#include "config_parser.hpp"

#include "xyz/openbmc_project/Common/error.hpp"
#include <phosphor-logging/elog-errors.hpp>

#include "config.h"
#include <exception>
#include <stdexcept>
#include <fstream>

namespace phosphor
{
namespace network
{

class TestConfigParser : public testing::Test
{
    public:
        config::Parser parser;
        TestConfigParser()
        {
            remove("/tmp/eth0.network");
            std::ofstream filestream("/tmp/eth0.network");

            filestream << "[Match]\nName=eth0\n" <<
                          "[Network]\nDHCP=true\n[DHCP]\nClientIdentifier= mac\n";
            filestream.close();
            parser.setFile("/tmp/eth0.network");
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

TEST_F(TestConfigParser, ReadConfigDataFromFile)
{
    auto values = parser.getValues("Network", "DHCP");
    std::string expectedValue = "true";
    bool found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("DHCP", "ClientIdentifier");
    expectedValue = "mac";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);

    values = parser.getValues("Match", "Name");
    expectedValue = "eth0";
    found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);
}

TEST_F(TestConfigParser, SectionNotExist)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    bool caughtException = false;
    try
    {
        parser.getValues("abc", "ipaddress");
    }
    catch (const std::exception& e)
    {
        caughtException = true;
    }
    EXPECT_EQ(true, caughtException);
}

TEST_F(TestConfigParser, KeyNotFound)
{
    using namespace sdbusplus::xyz::openbmc_project::Common::Error;
    bool caughtException = false;
    try
    {
        parser.getValues("Network", "abc");
    }
    catch (const std::exception& e)
    {
        caughtException = true;
    }
    EXPECT_EQ(true, caughtException);
    remove("/tmp/eth0.network");
}

}//namespace network
}//namespace phosphor

