#include "util.hpp"

#include <stdplus/raw.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

TEST(TestUtil, ValidateUnicast4)
{
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("1.1.1.1")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("192.168.1.0")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("10.30.0.1")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("8.8.4.4")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("169.253.255.255")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("169.254.0.1")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("169.254.255.255")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("169.255.0.0")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("240.0.0.0")));
    EXPECT_TRUE(validUnicast(ToAddr<in_addr>{}("255.255.255.1")));

    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("0.0.0.0")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("0.255.255.255")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("127.0.0.0")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("127.0.0.1")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("127.0.0.83")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("127.253.0.0")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("127.255.255.255")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("224.0.0.0")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("227.30.10.50")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("239.255.255.255")));
    EXPECT_FALSE(validUnicast(ToAddr<in_addr>{}("255.255.255.255")));
}

TEST(TestUtil, ValidateUnicast6)
{
    EXPECT_TRUE(validUnicast(ToAddr<in6_addr>{}("::2")));
    EXPECT_TRUE(validUnicast(ToAddr<in6_addr>{}("1::")));
    EXPECT_TRUE(validUnicast(ToAddr<in6_addr>{}("2001:5938::fd98")));
    EXPECT_TRUE(validUnicast(ToAddr<in6_addr>{}("fe80::1")));
    EXPECT_TRUE(validUnicast(ToAddr<in6_addr>{}("feff:ffff:ffff:ffff::")));

    EXPECT_FALSE(validUnicast(ToAddr<in6_addr>{}("::")));
    EXPECT_FALSE(validUnicast(ToAddr<in6_addr>{}("::1")));
    EXPECT_FALSE(validUnicast(ToAddr<in6_addr>{}("ff00::")));
    EXPECT_FALSE(
        validUnicast(ToAddr<in6_addr>{}("ffff:ffff:ffff:ffff:ffff::")));
}

TEST(TestUtil, AddrFromBuf)
{
    std::string tooSmall(1, 'a');
    std::string tooLarge(24, 'a');

    struct in_addr ip1 = {0x01020304};
    auto buf1 = stdplus::raw::asView<char>(ip1);
    InAddrAny res1 = addrFromBuf(AF_INET, buf1);
    EXPECT_EQ(ip1, res1);
    EXPECT_THROW(addrFromBuf(AF_INET, tooSmall), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_INET, tooLarge), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf1), std::invalid_argument);

    struct in6_addr ip2 = {0xfd, 0, 0, 0, 1};
    auto buf2 = stdplus::raw::asView<char>(ip2);
    InAddrAny res2 = addrFromBuf(AF_INET6, buf2);
    EXPECT_EQ(ip2, res2);
    EXPECT_THROW(addrFromBuf(AF_INET6, tooSmall), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_INET6, tooLarge), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf2), std::invalid_argument);
}

TEST(TestUtil, InterfaceToUbootEthAddr)
{
    EXPECT_EQ(std::nullopt, interfaceToUbootEthAddr("et"));
    EXPECT_EQ(std::nullopt, interfaceToUbootEthAddr("eth"));
    EXPECT_EQ(std::nullopt, interfaceToUbootEthAddr("sit0"));
    EXPECT_EQ(std::nullopt, interfaceToUbootEthAddr("ethh0"));
    EXPECT_EQ(std::nullopt, interfaceToUbootEthAddr("eth0h"));
    EXPECT_EQ("ethaddr", interfaceToUbootEthAddr("eth0"));
    EXPECT_EQ("eth1addr", interfaceToUbootEthAddr("eth1"));
    EXPECT_EQ("eth5addr", interfaceToUbootEthAddr("eth5"));
    EXPECT_EQ("eth28addr", interfaceToUbootEthAddr("eth28"));
}

namespace mac_address
{

TEST(MacIsEmpty, True)
{
    EXPECT_TRUE(isEmpty({}));
}

TEST(MacIsEmpty, False)
{
    EXPECT_FALSE(isEmpty({1}));
    EXPECT_FALSE(isEmpty({0, 0, 0, 1}));
    EXPECT_FALSE(isEmpty({0, 0, 0, 0, 0, 1}));
}

TEST(MacIsMulticast, True)
{
    EXPECT_TRUE(isMulticast({255, 255, 255, 255, 255, 255}));
    EXPECT_TRUE(isMulticast({1}));
}

TEST(MacIsMulticast, False)
{
    EXPECT_FALSE(isMulticast({0, 1, 2, 3, 4, 5}));
    EXPECT_FALSE(isMulticast({0xfe, 255, 255, 255, 255, 255}));
}

TEST(MacIsUnicast, True)
{
    EXPECT_TRUE(isUnicast({0, 1, 2, 3, 4, 5}));
    EXPECT_TRUE(isUnicast({0xfe, 255, 255, 255, 255, 255}));
}

TEST(MacIsUnicast, False)
{
    EXPECT_FALSE(isUnicast({}));
    EXPECT_FALSE(isUnicast({1}));
    EXPECT_FALSE(isUnicast({255, 255, 255, 255, 255, 255}));
}

TEST(IgnoredInterfaces, Empty)
{
    auto ret = internal::parseInterfaces({});
    EXPECT_TRUE(ret.empty());

    ret = internal::parseInterfaces(" ,  ,, ");
    EXPECT_TRUE(ret.empty());
}

TEST(IgnoredInterfaces, NotEmpty)
{
    using ::testing::ContainerEq;
    std::unordered_set<std::string_view> expected = {"eth0"};
    auto ret = internal::parseInterfaces("eth0");
    EXPECT_THAT(ret, ContainerEq(expected));

    expected = {"eth0", "eth1", "bond1", "usb0"};
    ret = internal::parseInterfaces(" ,eth0, eth1  ,bond1, usb0,,");
    EXPECT_THAT(ret, ContainerEq(expected));
}

} // namespace mac_address
} // namespace network
} // namespace phosphor
