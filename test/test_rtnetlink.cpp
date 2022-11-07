#include "rtnetlink.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <stdplus/raw.hpp>

#include <gtest/gtest.h>

namespace phosphor::network::netlink
{

TEST(AddrFromRtm, MissingAddr)
{
    struct
    {
        alignas(NLMSG_ALIGNTO) ifaddrmsg ifa = {};
    } msg;
    EXPECT_THROW(addrFromRtm(stdplus::raw::asView<char>(msg)),
                 std::runtime_error);
}

TEST(AddrFromRtm, Regular)
{
    struct
    {
        alignas(NLMSG_ALIGNTO) ifaddrmsg ifa;
        alignas(NLMSG_ALIGNTO) rtattr addr_hdr;
        alignas(NLMSG_ALIGNTO) uint8_t addr[4] = {192, 168, 1, 20};
    } msg;
    msg.ifa.ifa_family = AF_INET;
    msg.ifa.ifa_prefixlen = 28;
    msg.ifa.ifa_flags = 4;
    msg.ifa.ifa_scope = 3;
    msg.ifa.ifa_index = 10;
    msg.addr_hdr.rta_type = IFA_ADDRESS;
    msg.addr_hdr.rta_len = RTA_LENGTH(sizeof(msg.addr));

    auto ret = addrFromRtm(stdplus::raw::asView<char>(msg));
    EXPECT_EQ(msg.ifa.ifa_flags, ret.flags);
    EXPECT_EQ(msg.ifa.ifa_scope, ret.scope);
    EXPECT_EQ(msg.ifa.ifa_index, ret.ifidx);
    EXPECT_EQ((IfAddr{in_addr{hton(0xc0a80114)}, 28}), ret.ifaddr);
}

TEST(AddrFromRtm, ExtraFlags)
{
    struct
    {
        alignas(NLMSG_ALIGNTO) ifaddrmsg ifa = {};
        alignas(NLMSG_ALIGNTO) rtattr flags_hdr;
        alignas(NLMSG_ALIGNTO) uint32_t flags = 0xff00ff00;
        alignas(NLMSG_ALIGNTO) rtattr addr_hdr;
        alignas(NLMSG_ALIGNTO) uint8_t addr[16] = {};
    } msg;
    msg.ifa.ifa_family = AF_INET6;
    msg.flags_hdr.rta_type = IFA_FLAGS;
    msg.flags_hdr.rta_len = RTA_LENGTH(sizeof(msg.flags));
    msg.addr_hdr.rta_type = IFA_ADDRESS;
    msg.addr_hdr.rta_len = RTA_LENGTH(sizeof(msg.addr));

    auto ret = addrFromRtm(stdplus::raw::asView<char>(msg));
    EXPECT_EQ(0xff00ff00, ret.flags);
}

} // namespace phosphor::network::netlink
