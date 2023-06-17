#include "types.hpp"

#include <arpa/inet.h>
#include <fmt/chrono.h>
#include <fmt/format.h>

#include <array>
#include <sstream>
#include <string_view>

#include <gtest/gtest.h>

using std::literals::string_view_literals::operator""sv;

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

TEST(DecodeInt, uint8_10)
{
    DecodeInt<uint8_t, 10> d;
    EXPECT_EQ(42, d("42"));
    EXPECT_EQ(255, d("255"));
    EXPECT_THROW(d(""), std::invalid_argument);
    EXPECT_THROW(d("a0"), std::invalid_argument);
    EXPECT_THROW(d(".0"), std::invalid_argument);
    EXPECT_THROW(d("257"), std::overflow_error);
    EXPECT_THROW(d("300"), std::overflow_error);
}

TEST(DecodeInt, uint8_16)
{
    DecodeInt<uint8_t, 16> d;
    EXPECT_EQ(0x42, d("42"));
    EXPECT_EQ(0xff, d("ff"));
    EXPECT_THROW(d(""), std::invalid_argument);
    EXPECT_THROW(d("g0"), std::invalid_argument);
    EXPECT_THROW(d(".0"), std::invalid_argument);
    EXPECT_THROW(d("100"), std::overflow_error);
}

TEST(EncodeInt, uint8_10)
{
    EncodeInt<uint8_t, 10> e;
    static_assert(e.buf_size == 3);
    char buf[e.buf_size];
    EXPECT_EQ("0", std::string_view(buf, e(buf, 0)));
    EXPECT_EQ("42", std::string_view(buf, e(buf, 42)));
    EXPECT_EQ("255", std::string_view(buf, e(buf, 255)));
    EXPECT_EQ("000", std::string_view(buf, e(buf, 0, 3)));
    EXPECT_EQ("255", std::string_view(buf, e(buf, 255, 3)));
}

TEST(EncodeInt, uint8_16)
{
    EncodeInt<uint8_t, 16> e;
    static_assert(e.buf_size == 2);
    char buf[e.buf_size];
    EXPECT_EQ("0", std::string_view(buf, e(buf, 0)));
    EXPECT_EQ("2a", std::string_view(buf, e(buf, 42)));
    EXPECT_EQ("ff", std::string_view(buf, e(buf, 255)));
    EXPECT_EQ("00", std::string_view(buf, e(buf, 0, 2)));
    EXPECT_EQ("02", std::string_view(buf, e(buf, 2, 2)));
    EXPECT_EQ("ff", std::string_view(buf, e(buf, 255, 2)));
}

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

TEST(ToAddr, InAddr)
{
    EXPECT_THROW(ToAddr<in_addr>{}(""), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("0"), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("0.0.0"), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("0.0.0."), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}(".0.0.0"), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("0.0.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("x.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("ff.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ToAddr<in_addr>{}("256.0.0.0"), std::overflow_error);

    EXPECT_EQ((in_addr{}), ToAddr<in_addr>{}("0.0.0.0"));
    EXPECT_EQ((in_addr{htonl(0xc0a80101)}), ToAddr<in_addr>{}("192.168.001.1"));
}

TEST(ToAddr, In6Addr)
{
    constexpr ToAddr<in6_addr> ta;
    EXPECT_THROW(ta(""), std::invalid_argument);
    EXPECT_THROW(ta("0"), std::invalid_argument);
    EXPECT_THROW(ta("0:0"), std::invalid_argument);
    EXPECT_THROW(ta("0::0:"), std::invalid_argument);
    EXPECT_THROW(ta("0:::"), std::invalid_argument);
    EXPECT_THROW(ta(":::0"), std::invalid_argument);
    EXPECT_THROW(ta("0:::0"), std::invalid_argument);
    EXPECT_THROW(ta("0::0::0"), std::invalid_argument);
    EXPECT_THROW(ta("1::0.0.0."), std::invalid_argument);
    EXPECT_THROW(ta("1::.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ta("x::0"), std::invalid_argument);
    EXPECT_THROW(ta("g::0"), std::invalid_argument);
    EXPECT_THROW(ta("0:1:2:3:4::5:6:7"), std::invalid_argument);
    EXPECT_THROW(ta("::0:1:2:3:4:5:6:7"), std::invalid_argument);
    EXPECT_THROW(ta("0:1:2:3:4:5:6:7::"), std::invalid_argument);
    EXPECT_THROW(ta("0:1:2:3:4:5:6:7:8"), std::invalid_argument);
    EXPECT_THROW(ta("0:1:2:3:4:5:6:0.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ta("0:1:2:3:4:5::0.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ta("ffff0::0"), std::overflow_error);

    EXPECT_EQ((in6_addr{}), ta("::"));
    EXPECT_EQ((in6_addr{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                        255, 255, 255, 255, 255}),
              ta("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"sv));
    EXPECT_EQ((in6_addr{}), ta("0:0:0:0:0:0:0:0"));
    EXPECT_EQ((in6_addr{0, 0xff}), ta("ff::"));
    EXPECT_EQ((in6_addr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}),
              ta("::ff"));
    EXPECT_EQ((in6_addr{0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff}),
              ta("0:0:ff::ff"));
    EXPECT_EQ((in6_addr{0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 6, 0, 7, 0, 8}),
              ta("1:2:3:4::6:7:8"));
    EXPECT_EQ((in6_addr{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 0}),
              ta("1:2:3:4:5:6:7::"));
    EXPECT_EQ((in6_addr{0, 0, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8}),
              ta("::2:3:4:5:6:7:8"));
    EXPECT_EQ(
        (in6_addr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1}),
        ta("::ffff:192.168.0.1"));
    EXPECT_EQ((in6_addr{0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 168, 0, 1}),
              ta("ff::255.168.0.1"));
    EXPECT_EQ((in6_addr{0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 255, 168, 0, 1}),
              ta("0:1:2:3:4:5:255.168.0.1"));
}

TEST(ToAddr, InAddrAny)
{
    constexpr ToAddr<InAddrAny> ta;
    EXPECT_EQ((InAddrAny{in_addr{}}), ta("0.0.0.0"));
    EXPECT_EQ((InAddrAny{in6_addr{}}), ta("::"));
    EXPECT_EQ((InAddrAny{in6_addr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192,
                                  168, 0, 1}}),
              ta("::ffff:192.168.0.1"));
}

TEST(ToAddr, IfAddr)
{
    constexpr ToAddr<IfAddr> ta;
    EXPECT_THROW(ta("10"), std::invalid_argument);
    EXPECT_THROW(ta("/10"), std::invalid_argument);
    EXPECT_THROW(ta("0.0.0.0"), std::invalid_argument);
    EXPECT_THROW(ta("0.0.0.0/"), std::invalid_argument);
    EXPECT_EQ((IfAddr{in_addr{}, 0}), ta("0.0.0.0/0"));
    EXPECT_EQ((IfAddr{in_addr{}, 30}), ta("0.0.0.0/30"));
    EXPECT_EQ((IfAddr{in6_addr{}, 80}), ta("::/80"));
}

namespace detail
{

TEST(BufMaker, InAddr)
{
    ToStrBuf<in_addr> abm;
    EXPECT_EQ("255.255.255.255"sv, abm(in_addr{0xffffffff}));
    EXPECT_EQ("1.15.3.4"sv, abm(in_addr{htonl(0x010f0304)}));
    EXPECT_EQ("0.0.0.0"sv, abm(in_addr{}));
}

TEST(BufMaker, In6Addr)
{
    ToStrBuf<in6_addr> abm;
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
    EXPECT_EQ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"sv,
              abm(in6_addr{255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                           255, 255, 255, 255, 255, 255}));
    // rfc5952 4.2.2
    EXPECT_EQ("1:2:3:4:0:6:7:8"sv,
              abm(in6_addr{0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 6, 0, 7, 0, 8}));
    // rfc5952 4.2.3
    EXPECT_EQ("1::4:0:0:7:8"sv,
              abm(in6_addr{0, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 7, 0, 8}));
    // rfc5952 5
    EXPECT_EQ("::ffff:192.168.0.1"sv,
              abm(in6_addr{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168,
                           0, 1}));
}

TEST(BasicOps, AllAddrs)
{
    EXPECT_NE(InAddrAny{in6_addr{}}, InAddrAny{in_addr{}});

    EXPECT_EQ("a 0.0.0.1", fmt::format("a {}", in_addr{htonl(1)}));
    EXPECT_EQ("a 0.0.0.1", fmt::format("a {}", InAddrAny{in_addr{htonl(1)}}));
    EXPECT_EQ("a 100::", fmt::format("a {}", in6_addr{1}));
    EXPECT_EQ("a 100::", fmt::format("a {}", InAddrAny{in6_addr{1}}));
    EXPECT_EQ("a 100::/90", fmt::format("a {}", IfAddr{in6_addr{1}, 90}));

    EXPECT_EQ("0.0.0.1", std::to_string(in_addr{htonl(1)}));
    EXPECT_EQ("0.0.0.1", std::to_string(InAddrAny{in_addr{htonl(1)}}));
    EXPECT_EQ("100::", std::to_string(in6_addr{1}));
    EXPECT_EQ("100::", std::to_string(InAddrAny{in6_addr{1}}));
    EXPECT_EQ("100::/22", std::to_string(IfAddr{in6_addr{1}, 22}));

    EXPECT_EQ("a0.0.0.1",
              (std::stringstream{} << "a" << in_addr{htonl(1)}).str());
    EXPECT_EQ(
        "a0.0.0.1",
        (std::stringstream{} << "a" << InAddrAny{in_addr{htonl(1)}}).str());
    EXPECT_EQ("a100::", (std::stringstream{} << "a" << in6_addr{1}).str());
    EXPECT_EQ("a100::",
              (std::stringstream{} << "a" << InAddrAny{in6_addr{1}}).str());
    auto ss = std::stringstream{};
    constexpr auto addr = IfAddr{in6_addr{1}, 30};
    ss << "a" << addr;
    EXPECT_EQ("a100::/30", ss.str());

    EXPECT_NO_THROW(IfAddr(in6_addr{}, 128));
    EXPECT_NO_THROW(IfAddr(in_addr{}, 32));
    EXPECT_THROW(IfAddr(in6_addr{}, 129), std::invalid_argument);
    EXPECT_THROW(IfAddr(in_addr{}, 33), std::invalid_argument);
}

TEST(Perf, In6Addr)
{
    GTEST_SKIP();
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < 10000000; ++i)
    {
        ToStrBuf<in6_addr>{}(in6_addr{1});
    }
    fmt::print("Duration: {}\n", std::chrono::steady_clock::now() - start);
    // Make sure this test isn't enabled
    EXPECT_FALSE(true);
}

} // namespace detail
} // namespace phosphor::network
