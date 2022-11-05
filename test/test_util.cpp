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
