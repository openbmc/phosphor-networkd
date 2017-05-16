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

TEST_F(TestUtil, isLinLocaladdress)
{
    std::string ipaddress = "fe80:fec0::";
    EXPECT_TRUE(isLinkLocal(ipaddress));

    ipaddress = "2000:4567:789::";
    EXPECT_FALSE(isLinkLocal(ipaddress));

    ipaddress = "2000:fe80::";
    EXPECT_FALSE(isLinkLocal(ipaddress));
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

}// namespce network
}// namespace phosphor
