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

TEST(TestUtil, AddrFromBuf)
{
    std::string tooSmall(1, 'a');
    std::string tooLarge(24, 'a');

    stdplus::In4Addr ip1{1, 2, 3, 4};
    auto buf1 = stdplus::raw::asView<char>(ip1);
    auto res1 = addrFromBuf(AF_INET, buf1);
    EXPECT_EQ(ip1, res1);
    EXPECT_THROW(addrFromBuf(AF_INET, tooSmall), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_INET, tooLarge), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf1), std::invalid_argument);

    stdplus::In6Addr ip2{0xfd, 0, 0, 0, 1};
    auto buf2 = stdplus::raw::asView<char>(ip2);
    auto res2 = addrFromBuf(AF_INET6, buf2);
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

namespace internal
{

TEST(IsValidNtpServer, ValidIPv4)
{
    EXPECT_TRUE(isValidNtpServer("192.168.1.1"));
    EXPECT_TRUE(isValidNtpServer("10.0.0.1"));
    EXPECT_TRUE(isValidNtpServer("8.8.8.8"));
}

TEST(IsValidNtpServer, ValidIPv6)
{
    EXPECT_TRUE(isValidNtpServer("2001:db8::1"));
    EXPECT_TRUE(isValidNtpServer("fe80::1"));
    EXPECT_TRUE(isValidNtpServer("::1"));
}

TEST(IsValidNtpServer, ValidHostname)
{
    EXPECT_TRUE(isValidNtpServer("pool.ntp.org"));
    EXPECT_TRUE(isValidNtpServer("time.google.com"));
    EXPECT_TRUE(isValidNtpServer("ntp1.example.com"));
}

TEST(IsValidNtpServer, Invalid)
{
    EXPECT_FALSE(isValidNtpServer(""));
    EXPECT_FALSE(isValidNtpServer("not a valid server!"));
    EXPECT_FALSE(isValidNtpServer("192.168.1.256"));
    EXPECT_FALSE(isValidNtpServer("-invalid.host"));
}

} // namespace internal

TEST(IsIPv6LinkLocal, LinkLocalAddresses)
{
    EXPECT_TRUE(isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("fe80::1")));
    EXPECT_TRUE(isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("fe80::")));
    EXPECT_TRUE(isIPv6LinkLocal(
        stdplus::fromStr<stdplus::In6Addr>("fe80::aabb:ccdd:eeff")));
    EXPECT_TRUE(isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("febf::1")));
}

TEST(IsIPv6LinkLocal, NonLinkLocalAddresses)
{
    EXPECT_FALSE(
        isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("2001:db8::1")));
    EXPECT_FALSE(
        isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("fd00::1")));
    EXPECT_FALSE(isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("::1")));
    EXPECT_FALSE(isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("::")));
    EXPECT_FALSE(
        isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("ff02::1")));
    EXPECT_FALSE(
        isIPv6LinkLocal(stdplus::fromStr<stdplus::In6Addr>("fec0::1")));
}

} // namespace network
} // namespace phosphor
