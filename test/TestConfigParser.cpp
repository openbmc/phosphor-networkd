#include <gtest/gtest.h>

#include "config_parser.hpp"
#include "config.h"
#include <exception>
#include <stdexcept>

namespace phosphor
{
namespace network
{

class TestConfigParser : public testing::Test
{
    public:
        config::Parser parser;
        TestConfigParser() = default;

        bool isValueFound(std::vector<std::string> values, std::string expectedValue)
        {
            for (auto value : values)
            {
                if (expectedValue == value)
                {
                    return  true;
                }
            }
            return false;
        }


};

TEST_F(TestConfigParser, ReadConfigDataFromCache)
{
    remove("/tmp/eth0.network");
    parser.setFile("/tmp/eth0.network",
                   config::Parser::Mode::WRITE); //would be empty
    parser.setValue("Match", "Name", "eth0");

    parser.setValue("Network", "Address", "1.1.1.1");
    parser.setValue("Network", "Gateway", "2.2.2.2");
    parser.setValue("Network", "Address", "3.3.3.3");
    parser.setValue("Network", "Gateway", "4.4.4.4");
    parser.setValue("Link", "Mac", "1:2:3:4:5:6");
    auto values = parser.getValues("Network", "Address");
    std::string expectedValue = "3.3.3.3";
    bool found = isValueFound(values, expectedValue);

    EXPECT_EQ(found, true);
    parser.writeToFile();
}

TEST_F(TestConfigParser, ReadConfigDataFromFile)
{

    parser.setFile("/tmp/eth0.network", config::Parser::Mode::READ);
    auto values = parser.getValues("Network", "Gateway");
    std::string expectedValue = "2.2.2.2";
    bool found = isValueFound(values, expectedValue);

    EXPECT_EQ(found, true);
}

TEST_F(TestConfigParser, SectionNotExist)
{
    parser.setFile("/etc/systemd/network/eth0.network", config::Parser::Mode::READ);
    try
    {
        parser.getValues("abc", "ipaddress");
    }
    catch (const std::exception& e)
    {
        EXPECT_EQ(e.what(), std::string("Section not found"));
    }
}

TEST_F(TestConfigParser, KeyNotFound)
{
    parser.setFile("/tmp/eth0.network", config::Parser::Mode::READ);
    try
    {
        parser.getValues("Network", "abc");
    }
    catch (const std::exception& e)
    {
        EXPECT_EQ(e.what(), std::string("Key not found"));
    }
}

TEST_F(TestConfigParser, DeleteKey)
{
    parser.setFile("/tmp/eth0.network", config::Parser::Mode::READ);
    parser.remove("Network", "Address", "3.3.3.3");
    parser.remove("Network", "Gateway", "4.4.4.4");

    auto values = parser.getValues("Network", "Address");
    std::string expectedValue = "3.3.3.3";
    bool found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, false);
    parser.writeToFile();
}

TEST_F(TestConfigParser, ReadKeyAfterDelete)
{
    parser.setFile("/tmp/eth0.network", config::Parser::Mode::READ);
    auto values = parser.getValues("Network", "Address");
    std::string expectedValue = "1.1.1.1";
    bool found = isValueFound(values, expectedValue);
    EXPECT_EQ(found, true);
    remove("/tmp/eth0.network");
}

}//namespace network
}//namespace phosphor

