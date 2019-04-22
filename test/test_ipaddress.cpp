#include "ipaddress.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cstring>
#include <stdexcept>
#include <stdplus/raw.hpp>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{
namespace detail
{

TEST(ParseAddress, NotAddressType)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    EXPECT_THROW(parseAddress(filter, hdr, "", addresses), std::runtime_error);
    EXPECT_EQ(0, addresses.size());
}

TEST(ParseAddress, SmallMsg)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;
    std::string data = "1";
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    EXPECT_THROW(parseAddress(filter, hdr, data, addresses),
                 std::runtime_error);
    EXPECT_EQ(0, addresses.size());
}

TEST(ParseAddress, NoAttrs)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;
    ifaddrmsg msg{};
    msg.ifa_family = AF_INET;
    msg.ifa_prefixlen = 24;
    msg.ifa_index = 1;
    msg.ifa_scope = RT_SCOPE_UNIVERSE;
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    EXPECT_THROW(parseAddress(filter, hdr, data, addresses),
                 std::runtime_error);
    EXPECT_EQ(0, addresses.size());
}

TEST(ParseAddress, NoAddress)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;
    ifaddrmsg msg{};
    msg.ifa_family = AF_INET;
    msg.ifa_prefixlen = 24;
    msg.ifa_index = 1;
    msg.ifa_scope = RT_SCOPE_UNIVERSE;
    in_addr addr{};
    rtattr local{};
    constexpr auto len = RTA_LENGTH(sizeof(addr));
    local.rta_len = len;
    local.rta_type = IFA_LOCAL;
    char localbuf[RTA_ALIGN(len)];
    std::memset(localbuf, '\0', sizeof(localbuf));
    std::memcpy(localbuf, &local, sizeof(local));
    std::memcpy(RTA_DATA(localbuf), &addr, sizeof(addr));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&localbuf), sizeof(localbuf));
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    EXPECT_THROW(parseAddress(filter, hdr, data, addresses),
                 std::runtime_error);
    EXPECT_EQ(0, addresses.size());
}

TEST(ParseAddress, FilterInterface)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;
    ifaddrmsg msg{};
    msg.ifa_family = AF_INET;
    msg.ifa_prefixlen = 24;
    msg.ifa_index = 2;
    msg.ifa_scope = RT_SCOPE_UNIVERSE;
    in_addr addr;
    ASSERT_EQ(1, inet_pton(msg.ifa_family, "192.168.10.1", &addr));
    rtattr address{};
    constexpr auto len = RTA_LENGTH(sizeof(addr));
    address.rta_len = len;
    address.rta_type = IFA_ADDRESS;
    char addressbuf[RTA_ALIGN(len)];
    std::memset(addressbuf, '\0', sizeof(addressbuf));
    std::memcpy(addressbuf, &address, sizeof(address));
    std::memcpy(RTA_DATA(addressbuf), &addr, sizeof(addr));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&addressbuf), sizeof(addressbuf));
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    filter.interface = 1;
    parseAddress(filter, hdr, data, addresses);
    EXPECT_EQ(0, addresses.size());
    filter.interface = 2;
    parseAddress(filter, hdr, data, addresses);
    EXPECT_EQ(1, addresses.size());
    EXPECT_EQ(msg.ifa_index, addresses[0].interface);
    EXPECT_EQ(msg.ifa_scope, addresses[0].scope);
    EXPECT_EQ(msg.ifa_prefixlen, addresses[0].prefix);
    EXPECT_TRUE(
        stdplus::raw::equal(addr, std::get<in_addr>(addresses[0].address)));
}

TEST(ParseNeighbor, FilterScope)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;
    ifaddrmsg msg{};
    msg.ifa_family = AF_INET;
    msg.ifa_prefixlen = 24;
    msg.ifa_index = 2;
    msg.ifa_scope = RT_SCOPE_SITE;
    in_addr addr;
    ASSERT_EQ(1, inet_pton(msg.ifa_family, "192.168.10.1", &addr));
    rtattr address{};
    constexpr auto len = RTA_LENGTH(sizeof(addr));
    address.rta_len = len;
    address.rta_type = IFA_ADDRESS;
    char addressbuf[RTA_ALIGN(len)];
    std::memset(addressbuf, '\0', sizeof(addressbuf));
    std::memcpy(addressbuf, &address, sizeof(address));
    std::memcpy(RTA_DATA(addressbuf), &addr, sizeof(addr));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&addressbuf), sizeof(addressbuf));
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    filter.scope = RT_SCOPE_UNIVERSE;
    parseAddress(filter, hdr, data, addresses);
    EXPECT_EQ(0, addresses.size());
    filter.scope = RT_SCOPE_SITE;
    parseAddress(filter, hdr, data, addresses);
    EXPECT_EQ(1, addresses.size());
    EXPECT_EQ(msg.ifa_index, addresses[0].interface);
    EXPECT_EQ(msg.ifa_scope, addresses[0].scope);
    EXPECT_EQ(msg.ifa_prefixlen, addresses[0].prefix);
    EXPECT_TRUE(
        stdplus::raw::equal(addr, std::get<in_addr>(addresses[0].address)));
}

TEST(ParseNeighbor, NoFilter)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;
    ifaddrmsg msg{};
    msg.ifa_family = AF_INET6;
    msg.ifa_prefixlen = 24;
    msg.ifa_index = 1;
    msg.ifa_scope = RT_SCOPE_UNIVERSE;
    in6_addr addr;
    ASSERT_EQ(1, inet_pton(msg.ifa_family, "fd00::2", &addr));
    rtattr address{};
    constexpr auto len = RTA_LENGTH(sizeof(addr));
    address.rta_len = len;
    address.rta_type = IFA_ADDRESS;
    char addressbuf[RTA_ALIGN(len)];
    std::memset(addressbuf, '\0', sizeof(addressbuf));
    std::memcpy(addressbuf, &address, sizeof(address));
    std::memcpy(RTA_DATA(addressbuf), &addr, sizeof(addr));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&addressbuf), sizeof(addressbuf));
    AddressFilter filter;

    std::vector<AddressInfo> addresses;
    parseAddress(filter, hdr, data, addresses);
    EXPECT_EQ(1, addresses.size());
    EXPECT_EQ(msg.ifa_index, addresses[0].interface);
    EXPECT_EQ(msg.ifa_scope, addresses[0].scope);
    EXPECT_EQ(msg.ifa_prefixlen, addresses[0].prefix);
    EXPECT_TRUE(
        stdplus::raw::equal(addr, std::get<in6_addr>(addresses[0].address)));
}

} // namespace detail
} // namespace network
} // namespace phosphor
