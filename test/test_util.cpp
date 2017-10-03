#include <gtest/gtest.h>
#include <netinet/in.h>
#include "util.hpp"

namespace phosphor
{
namespace network
{

class TestUtil : public testing::Test
{
    public:
        TestUtil()
        {
            // Empty
        }

};

TEST_F(TestUtil, ConvertV4MasktoPrefix)
{
    std::string mask = "255.255.255.0";
    uint8_t prefix = toCidr(AF_INET, mask);
    EXPECT_EQ(prefix, 24);

    mask = "255.255.0.0";
    prefix = toCidr(AF_INET, mask);
    EXPECT_EQ(prefix, 16);

    mask = "255.0.0.0";
    prefix = toCidr(AF_INET, mask);
    EXPECT_EQ(prefix, 8);

    mask = "255.224.0.0";
    prefix = toCidr(AF_INET, mask);
    EXPECT_EQ(prefix, 11);

    //Invalid Mask
    mask = "255.0.255.0";
    prefix = toCidr(AF_INET, mask);
    EXPECT_EQ(prefix, 0);
}

TEST_F(TestUtil, convertV6MasktoPrefix)
{
    std::string mask = "ffff:ffff::";
    uint8_t prefix = toCidr(AF_INET6, mask);
    EXPECT_EQ(prefix, 32);

    mask = "ffff:ffff:ffff::";
    prefix = toCidr(AF_INET6, mask);
    EXPECT_EQ(prefix, 48);

    mask = "ffff:ffff:fc00::";
    prefix = toCidr(AF_INET6, mask);
    EXPECT_EQ(prefix, 38);

    //Invalid Mask
    mask = "ffff:0fff::";
    prefix = toCidr(AF_INET6, mask);
    EXPECT_EQ(prefix, 0);
}

TEST_F(TestUtil, isLinkLocaladdress)
{
    std::string ipaddress = "fe80:fec0::";
    EXPECT_TRUE(isLinkLocalIP(ipaddress, "ipv6"));

    ipaddress = "2000:4567:789::";
    EXPECT_FALSE(isLinkLocalIP(ipaddress, "ipv6"));

    ipaddress = "2000:fe80::";
    EXPECT_TRUE(isLinkLocalIP(ipaddress, "ipv6"));
}

TEST_F(TestUtil, convertPrefixToMask)
{
    std::string mask = toMask(AF_INET, 24);
    EXPECT_EQ(mask, "255.255.255.0");

    mask = toMask(AF_INET, 8);
    EXPECT_EQ(mask, "255.0.0.0");

    mask = toMask(AF_INET, 27);
    EXPECT_EQ(mask, "255.255.255.224");
}

TEST_F(TestUtil, getNetworkAddress)
{
    std::string address = getNetworkID(AF_INET,"9.3.23.251",24);
    EXPECT_EQ("9.3.23.0",address);

    address = getNetworkID(AF_INET,"9.3.23.251",25);
    EXPECT_EQ("9.3.23.128",address);

    address = getNetworkID(AF_INET6,"2001:db8:abcd:dd12::0",64);
    EXPECT_EQ("2001:db8:abcd:dd12::",address);

    address = getNetworkID(AF_INET,"a.b.c.d",25);
    EXPECT_EQ("",address);

    address = getNetworkID(AF_INET6,"2001:db8:gghh:dd12::0",64);
    EXPECT_EQ("",address);


    address = getNetworkID(AF_INET6,"fe80::201:6cff:fe80:228",64);
    EXPECT_EQ("fe80::",address);
}

}// namespce network
}// namespace phosphor
