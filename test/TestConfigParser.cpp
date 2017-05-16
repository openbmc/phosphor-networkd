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

};

TEST_F(TestConfigParser, ReadConfigDataFromCache)
{
    remove("/tmp/eth0.network");
    parser.setFile("/tmp/eth0.network");//would be empty
    parser.setValue("Network","Gateway","1.1.1.1");
    parser.setValue("Network","ipaddress","2.2.2.2");
    parser.setValue("Link","Mac","1:2:3:4:5:6");

    EXPECT_EQ("2.2.2.2", parser.getValue("Network","ipaddress"));
    EXPECT_EQ("1.1.1.1", parser.getValue("Network","Gateway"));
    parser.writeToFile();
}

TEST_F(TestConfigParser, ReadConfigDataFromFile)
{
    parser.setFile("/tmp/eth0.network");

    EXPECT_EQ("2.2.2.2", parser.getValue("Network","ipaddress"));
    EXPECT_EQ("1.1.1.1", parser.getValue("Network","Gateway"));
}

TEST_F(TestConfigParser, SectionNotExist)
{
    parser.setFile("/etc/systemd/network/eth0.network");
    try
    {
        parser.getValue("abc","ipaddress");
    }
    catch(const std::exception& e)
    {
        EXPECT_EQ(e.what(),std::string("Section not found"));
    }
}

TEST_F(TestConfigParser, KeyNotFound)
{
    parser.setFile("/tmp/eth0.network");
    try
    {
        parser.getValue("Network","abc");
    }
    catch(const std::exception& e)
    {
        EXPECT_EQ(e.what(),std::string("Key not found"));
    }
}

TEST_F(TestConfigParser, DeleteKey)
{
    parser.setFile("/tmp/eth0.network");
    try
    {
        parser.getValue("Network","ipaddress");
        EXPECT_EQ("2.2.2.2", parser.getValue("Network","ipaddress"));
        parser.removeKey("Network","ipaddress");
        parser.getValue("Network","ipaddress");
    }
    catch(const std::exception& e)
    {
        EXPECT_EQ(e.what(),std::string("Key not found"));
    }
    remove("/tmp/eth0.network");
}
}//namespace network
}//namespace phosphor

