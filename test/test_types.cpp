#include "types.hpp"

#include <arpa/inet.h>
#include <fmt/chrono.h>
#include <fmt/format.h>

#include <sstream>
#include <string_view>

#include <gtest/gtest.h>

using std::literals::string_view_literals::operator""sv;

TEST(EqualOperator, EthAddr)
{
    EXPECT_EQ((ether_addr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}),
              (ether_addr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}));
    EXPECT_EQ((ether_addr{}), (ether_addr{}));
    EXPECT_NE((ether_addr{1}), (ether_addr{}));
}

TEST(EqualOperator, InAddr)
{
    EXPECT_EQ((in_addr{0xff00ff00}), (in_addr{0xff00ff00}));
    EXPECT_EQ((in_addr{}), (in_addr{}));
    EXPECT_NE((in_addr{1}), (in_addr{}));
}

TEST(EqualOperator, In6Addr)
{
    EXPECT_EQ((in6_addr{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}),
              (in6_addr{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}));
    EXPECT_EQ((in6_addr{}), (in6_addr{}));
    EXPECT_NE((in6_addr{1}), (in6_addr{}));
}

namespace phosphor::network
{

TEST(EqualOperator, InAddrAny)
{
    EXPECT_EQ(InAddrAny(in6_addr{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0xff}),
              (in6_addr{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}));
    EXPECT_NE(InAddrAny(in6_addr{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0xff}),
              (in_addr{}));
    EXPECT_EQ((in6_addr{}), InAddrAny(in6_addr{}));
    EXPECT_NE((in_addr{}), InAddrAny(in6_addr{}));
    EXPECT_NE(InAddrAny(in6_addr{1}), InAddrAny(in6_addr{}));
}

namespace detail
{

TEST(BufMaker, EthAddr)
{
    AddrBufMaker<ether_addr> abm;
    EXPECT_EQ("11:22:33:44:55:66"sv,
              abm(ether_addr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}));
    EXPECT_EQ("01:02:03:04:05:67"sv,
              abm(ether_addr{0x01, 0x02, 0x03, 0x04, 0x05, 0x67}));
    EXPECT_EQ("00:00:00:00:00:00"sv,
              abm(ether_addr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
}

TEST(BufMaker, InAddr)
{
    AddrBufMaker<in_addr> abm;
    EXPECT_EQ("255.255.255.255"sv, abm(in_addr{0xffffffff}));
    EXPECT_EQ("1.15.3.4"sv, abm(in_addr{htonl(0x010f0304)}));
    EXPECT_EQ("0.0.0.0"sv, abm(in_addr{}));
}

TEST(BufMaker, In6Addr)
{
    AddrBufMaker<in6_addr> abm;
    EXPECT_EQ("::"sv, abm(in6_addr{}));
    EXPECT_EQ("ff::"sv, abm(in6_addr{0, 0xff}));
    EXPECT_EQ("::ff"sv,
              abm(in6_addr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}));
    EXPECT_EQ("0:0:ff::ff"sv, abm(in6_addr{0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0xff}));
    EXPECT_EQ("::100:0:ff"sv,
              abm(in6_addr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xff}));
    EXPECT_EQ("ff00::"sv, abm(in6_addr{0xff}));
    EXPECT_EQ("1:2:3:4:5:6:7:8"sv,
              abm(in6_addr{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}));
}

TEST(BasicOps, AllAddrs)
{
    EXPECT_NE(InAddrAny{in6_addr{}}, InAddrAny{in_addr{}});

    EXPECT_EQ("a 01:00:00:00:00:00", fmt::format("a {}", ether_addr{1}));
    EXPECT_EQ("a 0.0.0.1", fmt::format("a {}", in_addr{htonl(1)}));
    EXPECT_EQ("a 0.0.0.1", fmt::format("a {}", InAddrAny{in_addr{htonl(1)}}));
    EXPECT_EQ("a 100::", fmt::format("a {}", in6_addr{1}));
    EXPECT_EQ("a 100::", fmt::format("a {}", InAddrAny{in6_addr{1}}));

    EXPECT_EQ("01:00:00:00:00:00", std::to_string(ether_addr{1}));
    EXPECT_EQ("0.0.0.1", std::to_string(in_addr{htonl(1)}));
    EXPECT_EQ("0.0.0.1", std::to_string(InAddrAny{in_addr{htonl(1)}}));
    EXPECT_EQ("100::", std::to_string(in6_addr{1}));
    EXPECT_EQ("100::", std::to_string(InAddrAny{in6_addr{1}}));

    EXPECT_EQ("a01:00:00:00:00:00",
              (std::stringstream{} << "a" << ether_addr{1}).str());
    EXPECT_EQ("a0.0.0.1",
              (std::stringstream{} << "a" << in_addr{htonl(1)}).str());
    EXPECT_EQ(
        "a0.0.0.1",
        (std::stringstream{} << "a" << InAddrAny{in_addr{htonl(1)}}).str());
    EXPECT_EQ("a100::", (std::stringstream{} << "a" << in6_addr{1}).str());
    EXPECT_EQ("a100::",
              (std::stringstream{} << "a" << InAddrAny{in6_addr{1}}).str());
}

TEST(Perf, In6Addr)
{
    GTEST_SKIP();
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < 10000000; ++i)
    {
        AddrBufMaker<in6_addr>{}(in6_addr{1});
    }
    fmt::print("Duration: {}\n", std::chrono::steady_clock::now() - start);
    // Make sure this test isn't enabled
    EXPECT_FALSE(true);
}

} // namespace detail
} // namespace phosphor::network
