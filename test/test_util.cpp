#include "util.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Common/error.hpp>

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
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf1), std::runtime_error);

    struct in6_addr ip2;
    EXPECT_EQ(1, inet_pton(AF_INET6, "fdd8:b5ad:9d93:94ee::2:1", &ip2));
    std::string_view buf2(reinterpret_cast<char*>(&ip2), sizeof(ip2));
    InAddrAny res2 = addrFromBuf(AF_INET6, buf2);
    EXPECT_EQ(0, memcmp(&ip2, &std::get<struct in6_addr>(res2), sizeof(ip2)));
    EXPECT_THROW(addrFromBuf(AF_INET6, tooSmall), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_INET6, tooLarge), std::runtime_error);
    EXPECT_THROW(addrFromBuf(AF_UNSPEC, buf2), std::runtime_error);
}

TEST_F(TestUtil, IpToString)
{
    struct in_addr ip1;
    EXPECT_EQ(1, inet_pton(AF_INET, "192.168.10.1", &ip1));
    EXPECT_EQ("192.168.10.1", toString(InAddrAny(ip1)));

    struct in6_addr ip2;
    EXPECT_EQ(1, inet_pton(AF_INET6, "fdd8:b5ad:9d93:94ee::2:1", &ip2));
    EXPECT_EQ("fdd8:b5ad:9d93:94ee::2:1", toString(InAddrAny(ip2)));

    InAddrAny ip3;
    try
    {
        struct E
        {
            operator struct in6_addr()
            {
                throw 1;
            }
        };
        ip3.emplace<struct in6_addr>(E());
        EXPECT_TRUE(false);
    }
    catch (...)
    {
    }
    EXPECT_THROW(toString(ip3), std::runtime_error);
}

TEST_F(TestUtil, IpValidation)
{
    std::string ipaddress = "0.0.0.0";
    EXPECT_EQ(true, isValidIP(AF_INET, ipaddress));

    ipaddress = "9.3.185.83";
    EXPECT_EQ(true, isValidIP(AF_INET, ipaddress));

    ipaddress = "9.3.185.a";
    EXPECT_EQ(false, isValidIP(AF_INET, ipaddress));

    ipaddress = "9.3.a.83";
    EXPECT_EQ(false, isValidIP(AF_INET, ipaddress));

    ipaddress = "x.x.x.x";
    EXPECT_EQ(false, isValidIP(AF_INET, ipaddress));

    ipaddress = "0:0:0:0:0:0:0:0";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));

    ipaddress = "1:0:0:0:0:0:0:8";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));

    ipaddress = "1::8";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));

    ipaddress = "0:0:0:0:0:FFFF:204.152.189.116";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));

    ipaddress = "::ffff:204.152.189.116";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));

    ipaddress = "a:0:0:0:0:FFFF:204.152.189.116";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));

    ipaddress = "1::8";
    EXPECT_EQ(true, isValidIP(AF_INET6, ipaddress));
}

TEST_F(TestUtil, PrefixValidation)
{
    uint8_t prefixLength = 1;
    EXPECT_EQ(true, isValidPrefix(AF_INET, prefixLength));

    prefixLength = 32;
    EXPECT_EQ(true, isValidPrefix(AF_INET, prefixLength));

    prefixLength = 0;
    EXPECT_EQ(false, isValidPrefix(AF_INET, prefixLength));

    prefixLength = 33;
    EXPECT_EQ(false, isValidPrefix(AF_INET, prefixLength));

    prefixLength = 33;
    EXPECT_EQ(true, isValidPrefix(AF_INET6, prefixLength));

    prefixLength = 65;
    EXPECT_EQ(false, isValidPrefix(AF_INET, prefixLength));
}

TEST_F(TestUtil, MacValidation)
{
    std::string macaddress = "00:00:00:00:00:00";
    EXPECT_EQ(false, phosphor::network::mac_address::validate(macaddress));

    macaddress = "F6:C6:E6:6:B0:D3";
    EXPECT_EQ(true, phosphor::network::mac_address::validate(macaddress));

    macaddress = "F6:C6:E6:06:B0:D3";
    EXPECT_EQ(true, phosphor::network::mac_address::validate(macaddress));

    macaddress = "hh:HH:HH:hh:HH:yy";
    EXPECT_EQ(false, phosphor::network::mac_address::validate(macaddress));

    macaddress = "hhh:GGG:iii:jjj:kkk:lll";
    EXPECT_EQ(false, phosphor::network::mac_address::validate(macaddress));
}

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

    // Invalid Mask
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

    // Invalid Mask
    mask = "ffff:0fff::";
    prefix = toCidr(AF_INET6, mask);
    EXPECT_EQ(prefix, 0);
}

TEST_F(TestUtil, isLinkLocaladdress)
{
    std::string ipaddress = "fe80:fec0::";
    EXPECT_TRUE(isLinkLocalIP(ipaddress));

    ipaddress = "2000:fe80:789::";
    EXPECT_FALSE(isLinkLocalIP(ipaddress));

    ipaddress = "2000:fe80::";
    EXPECT_FALSE(isLinkLocalIP(ipaddress));

    ipaddress = "169.254.3.3";
    EXPECT_TRUE(isLinkLocalIP(ipaddress));

    ipaddress = "3.169.254.3";
    EXPECT_FALSE(isLinkLocalIP(ipaddress));

    ipaddress = "3.3.169.254";
    EXPECT_FALSE(isLinkLocalIP(ipaddress));
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
    std::string address = getNetworkID(AF_INET, "9.3.23.251", 24);
    EXPECT_EQ("9.3.23.0", address);

    address = getNetworkID(AF_INET, "9.3.23.251", 25);
    EXPECT_EQ("9.3.23.128", address);

    address = getNetworkID(AF_INET6, "2001:db8:abcd:dd12::0", 64);
    EXPECT_EQ("2001:db8:abcd:dd12::", address);

    EXPECT_THROW(getNetworkID(AF_INET, "a.b.c.d", 25), InternalFailure);

    EXPECT_THROW(getNetworkID(AF_INET6, "2001:db8:gghh:dd12::0", 64),
                 InternalFailure);

    address = getNetworkID(AF_INET6, "fe80::201:6cff:fe80:228", 64);
    EXPECT_EQ("fe80::", address);
}

TEST_F(TestUtil, CopyFromTooSmall)
{
    constexpr auto expected = "abcde"sv;
    struct
    {
        uint8_t data[10];
    } data;
    static_assert(sizeof(data) > expected.size());
    EXPECT_THROW(copyFrom<decltype(data)>(expected), std::runtime_error);
}

TEST_F(TestUtil, CopyFromSome)
{
    constexpr auto expected = "abcde"sv;
    struct
    {
        uint8_t data[2];
    } data;
    static_assert(sizeof(data) < expected.size());
    data = copyFrom<decltype(data)>(expected);
    EXPECT_EQ(0, memcmp(&data, expected.data(), sizeof(data)));
}

TEST_F(TestUtil, CopyFromAll)
{
    constexpr auto expected = "abcde"sv;
    struct
    {
        uint8_t data[5];
    } data;
    static_assert(sizeof(data) == expected.size());
    data = copyFrom<decltype(data)>(expected);
    EXPECT_EQ(0, memcmp(&data, expected.data(), sizeof(data)));
}

TEST_F(TestUtil, ExtractSome)
{
    constexpr auto expected = "abcde"sv;
    auto buf = expected;
    struct
    {
        uint8_t data[2];
    } data;
    static_assert(sizeof(data) < expected.size());
    data = extract<decltype(data)>(buf);
    EXPECT_EQ(0, memcmp(&data, expected.data(), sizeof(data)));
    EXPECT_EQ(3, buf.size());
    EXPECT_EQ(expected.substr(2), buf);
}

TEST_F(TestUtil, ExtractAll)
{
    constexpr auto expected = "abcde"sv;
    auto buf = expected;
    struct
    {
        uint8_t data[5];
    } data;
    static_assert(sizeof(data) == expected.size());
    data = extract<decltype(data)>(buf);
    EXPECT_EQ(0, memcmp(&data, expected.data(), sizeof(data)));
    EXPECT_EQ(0, buf.size());
}

TEST_F(TestUtil, Equal)
{
    struct
    {
        int i;
    } a, b{};
    a.i = 4;
    b.i = 4;

    EXPECT_TRUE(equal(a, b));
}

TEST_F(TestUtil, NotEqual)
{
    struct
    {
        int i;
    } a, b{};
    a.i = 2;
    b.i = 4;

    EXPECT_FALSE(equal(a, b));
}

} // namespace network
} // namespace phosphor
