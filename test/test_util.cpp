#include "util.hpp"

#include <arpa/inet.h>
#include <fmt/chrono.h>
#include <netinet/in.h>

#include <charconv>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

using namespace std::literals;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
class TestUtil : public testing::Test
{
  public:
    TestUtil()
    {
        // Empty
    }
};

TEST_F(TestUtil, AddrFromBuf)
{
    std::string tooSmall(1, 'a');
    std::string tooLarge(24, 'a');

    struct in_addr ip1;
    EXPECT_EQ(1, inet_pton(AF_INET, "192.168.10.1", &ip1));
    std::string_view buf1(reinterpret_cast<char*>(&ip1), sizeof(ip1));
    InAddrAny res1 = addrFromBuf(AF_INET, buf1);
    EXPECT_EQ(0, memcmp(&ip1, &std::get<struct in_addr>(res1), sizeof(ip1)));
    EXPECT_THROW(addrFromBuf(AF_INET, tooSmall), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_INET, tooLarge), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf1), std::invalid_argument);

    struct in6_addr ip2;
    EXPECT_EQ(1, inet_pton(AF_INET6, "fdd8:b5ad:9d93:94ee::2:1", &ip2));
    std::string_view buf2(reinterpret_cast<char*>(&ip2), sizeof(ip2));
    InAddrAny res2 = addrFromBuf(AF_INET6, buf2);
    EXPECT_EQ(0, memcmp(&ip2, &std::get<struct in6_addr>(res2), sizeof(ip2)));
    EXPECT_THROW(addrFromBuf(AF_INET6, tooSmall), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_INET6, tooLarge), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf2), std::invalid_argument);
}

TEST_F(TestUtil, IpValidation)
{
    EXPECT_TRUE(isValidIP(AF_INET, "0.0.0.0"));
    EXPECT_TRUE(isValidIP("0.0.0.0"));

    EXPECT_TRUE(isValidIP(AF_INET, "9.3.185.83"));

    EXPECT_FALSE(isValidIP(AF_INET, "9.3.185.a"));
    EXPECT_FALSE(isValidIP("9.3.185.a"));

    EXPECT_FALSE(isValidIP(AF_INET, "9.3.a.83"));

    EXPECT_FALSE(isValidIP(AF_INET, "x.x.x.x"));

    EXPECT_TRUE(isValidIP(AF_INET6, "0:0:0:0:0:0:0:0"));
    EXPECT_TRUE(isValidIP("0:0:0:0:0:0:0:0"));

    EXPECT_TRUE(isValidIP(AF_INET6, "1:0:0:0:0:0:0:8"));

    EXPECT_TRUE(isValidIP(AF_INET6, "1::8"));

    EXPECT_TRUE(isValidIP(AF_INET6, "0:0:0:0:0:FFFF:204.152.189.116"));

    EXPECT_TRUE(isValidIP(AF_INET6, "::ffff:204.152.189.116"));

    EXPECT_TRUE(isValidIP(AF_INET6, "a:0:0:0:0:FFFF:204.152.189.116"));

    EXPECT_TRUE(isValidIP(AF_INET6, "1::8"));
}

TEST_F(TestUtil, PrefixValidation)
{
    EXPECT_TRUE(isValidPrefix(AF_INET, 0));
    EXPECT_TRUE(isValidPrefix(AF_INET, 1));
    EXPECT_TRUE(isValidPrefix(AF_INET, 32));
    EXPECT_FALSE(isValidPrefix(AF_INET, 33));
    EXPECT_FALSE(isValidPrefix(AF_INET, 64));

    EXPECT_TRUE(isValidPrefix(AF_INET6, 0));
    EXPECT_TRUE(isValidPrefix(AF_INET6, 1));
    EXPECT_TRUE(isValidPrefix(AF_INET6, 53));
    EXPECT_TRUE(isValidPrefix(AF_INET6, 64));
    EXPECT_TRUE(isValidPrefix(AF_INET6, 128));
    EXPECT_FALSE(isValidPrefix(AF_INET6, 129));
    EXPECT_FALSE(isValidPrefix(AF_INET6, 177));

    EXPECT_THROW(isValidPrefix(AF_UNSPEC, 1), std::invalid_argument);
}

TEST_F(TestUtil, InterfaceToUbootEthAddr)
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

TEST(MacFromString, Bad)
{
    EXPECT_THROW(fromString("0x:00:00:00:00:00"), std::invalid_argument);
    EXPECT_THROW(fromString("00:00:00:00:00"), std::invalid_argument);
    EXPECT_THROW(fromString("00:00:00:00:00:"), std::invalid_argument);
    EXPECT_THROW(fromString("00:00:00:00::00"), std::invalid_argument);
    EXPECT_THROW(fromString(":00:00:00:00:00"), std::invalid_argument);
    EXPECT_THROW(fromString("00::00:00:00:00"), std::invalid_argument);
    EXPECT_THROW(fromString(":::::"), std::invalid_argument);
    EXPECT_THROW(fromString("00:0:0:0:0"), std::invalid_argument);
    EXPECT_THROW(fromString("00:00:00:00:00:00:00"), std::invalid_argument);
    EXPECT_THROW(fromString(""), std::invalid_argument);
    EXPECT_THROW(fromString("123456789XYZ"), std::invalid_argument);
    EXPECT_THROW(fromString("123456789AB"), std::invalid_argument);
    EXPECT_THROW(fromString("123456789ABCD"), std::invalid_argument);
}

TEST(MacFromString, Valid)
{
    EXPECT_EQ((ether_addr{}), fromString("00:00:00:00:00:00"));
    EXPECT_EQ((ether_addr{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}),
              fromString("FF:EE:DD:cc:bb:aa"));
    EXPECT_EQ((ether_addr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}),
              fromString("0:1:2:3:4:5"));
    EXPECT_EQ((ether_addr{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}),
              fromString("0123456789AB"));
    EXPECT_EQ((ether_addr{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}),
              fromString("FFEEDDccbbaa"));
}

TEST(MacIsEmpty, True)
{
    EXPECT_TRUE(isEmpty({}));
}

TEST(MacIsEmpty, False)
{
    EXPECT_FALSE(isEmpty(fromString("01:00:00:00:00:00")));
    EXPECT_FALSE(isEmpty(fromString("00:00:00:10:00:00")));
    EXPECT_FALSE(isEmpty(fromString("00:00:00:00:00:01")));
}

TEST(MacIsMulticast, True)
{
    EXPECT_TRUE(isMulticast(fromString("ff:ff:ff:ff:ff:ff")));
    EXPECT_TRUE(isMulticast(fromString("01:00:00:00:00:00")));
}

TEST(MacIsMulticast, False)
{
    EXPECT_FALSE(isMulticast(fromString("00:11:22:33:44:55")));
    EXPECT_FALSE(isMulticast(fromString("FE:11:22:33:44:55")));
}

TEST(MacIsUnicast, True)
{
    EXPECT_TRUE(isUnicast(fromString("00:11:22:33:44:55")));
    EXPECT_TRUE(isUnicast(fromString("FE:11:22:33:44:55")));
}

TEST(MacIsUnicast, False)
{
    EXPECT_FALSE(isUnicast(fromString("00:00:00:00:00:00")));
    EXPECT_FALSE(isUnicast(fromString("01:00:00:00:00:00")));
    EXPECT_FALSE(isUnicast(fromString("ff:ff:ff:ff:ff:ff")));
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
