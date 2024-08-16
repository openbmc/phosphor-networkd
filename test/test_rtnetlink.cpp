#include "rtnetlink.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <stdplus/raw.hpp>

#include <gtest/gtest.h>

namespace phosphor::network::netlink
{

using stdplus::operator""_sub;
using stdplus::operator""_ip;

TEST(IntfFromRtm, SmallMsg)
{
    EXPECT_THROW(intfFromRtm("1"), std::runtime_error);
}

TEST(IntfFromRtm, NoAttrs)
{
    struct
    {
        ifinfomsg hdr __attribute__((aligned(NLMSG_ALIGNTO)));
    } msg;
    msg.hdr.ifi_type = 3;
    msg.hdr.ifi_index = 1;
    msg.hdr.ifi_flags = 2;
    EXPECT_EQ(intfFromRtm(stdplus::raw::asView<char>(msg)),
              (InterfaceInfo{.type = 3, .idx = 1, .flags = 2}));
}

TEST(IntfFromRtm, AllAttrs)
{
    struct
    {
        ifinfomsg hdr __attribute__((aligned(NLMSG_ALIGNTO)));
        rtattr addr_hdr __attribute__((aligned((RTA_ALIGNTO))));
        char addr[6]
            __attribute__((aligned((RTA_ALIGNTO)))) = {0, 1, 2, 3, 4, 5};
        rtattr name_hdr __attribute__((aligned((RTA_ALIGNTO))));
        char name[5] __attribute__((aligned((RTA_ALIGNTO)))) = "eth0";
        rtattr mtu_hdr __attribute__((aligned((RTA_ALIGNTO))));
        unsigned mtu __attribute__((aligned((RTA_ALIGNTO)))) = 50;
    } msg;
    msg.hdr.ifi_type = 4;
    msg.hdr.ifi_index = 1;
    msg.hdr.ifi_flags = 2;
    msg.addr_hdr.rta_type = IFLA_ADDRESS;
    msg.addr_hdr.rta_len = RTA_LENGTH(sizeof(msg.addr));
    msg.name_hdr.rta_type = IFLA_IFNAME;
    msg.name_hdr.rta_len = RTA_LENGTH(sizeof(msg.name));
    msg.mtu_hdr.rta_type = IFLA_MTU;
    msg.mtu_hdr.rta_len = RTA_LENGTH(sizeof(msg.mtu));

    auto info = intfFromRtm(stdplus::raw::asView<char>(msg));
    auto expected = InterfaceInfo{
        .type = 4,
        .idx = 1,
        .flags = 2,
        .name = "eth0",
        .mac = ether_addr{0, 1, 2, 3, 4, 5},
        .mtu = 50};
    EXPECT_EQ(info, expected);
}

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
    EXPECT_EQ("192.168.1.20/28"_sub, ret.ifaddr);
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

TEST(NeighFromRtm, MissingAddr)
{
    struct
    {
        alignas(NLMSG_ALIGNTO) ndmsg ndm = {};
    } msg;

    EXPECT_EQ((NeighborInfo{}), neighFromRtm(stdplus::raw::asView<char>(msg)));
}

TEST(NeighFromRtm, NoMac)
{
    struct
    {
        alignas(NLMSG_ALIGNTO) ndmsg ndm;
        alignas(NLMSG_ALIGNTO) rtattr addr_hdr;
        alignas(NLMSG_ALIGNTO) uint8_t addr[4] = {192, 168, 1, 20};
    } msg;
    msg.ndm.ndm_family = AF_INET;
    msg.ndm.ndm_state = 4;
    msg.addr_hdr.rta_type = NDA_DST;
    msg.addr_hdr.rta_len = RTA_LENGTH(sizeof(msg.addr));

    auto ret = neighFromRtm(stdplus::raw::asView<char>(msg));
    EXPECT_EQ(msg.ndm.ndm_state, ret.state);
    EXPECT_EQ("192.168.1.20"_ip, ret.addr);
    EXPECT_FALSE(ret.mac);
}

TEST(NeighFromRtm, Full)
{
    struct
    {
        alignas(NLMSG_ALIGNTO) ndmsg ndm;
        alignas(NLMSG_ALIGNTO) rtattr addr_hdr;
        alignas(NLMSG_ALIGNTO) uint8_t addr[4] = {192, 168, 1, 20};
        alignas(NLMSG_ALIGNTO) rtattr mac_hdr;
        alignas(NLMSG_ALIGNTO) uint8_t mac[6] = {1, 2, 3, 4, 5, 6};
    } msg;
    msg.ndm.ndm_family = AF_INET;
    msg.addr_hdr.rta_type = NDA_DST;
    msg.addr_hdr.rta_len = RTA_LENGTH(sizeof(msg.addr));
    msg.mac_hdr.rta_type = NDA_LLADDR;
    msg.mac_hdr.rta_len = RTA_LENGTH(sizeof(msg.mac));

    auto ret = neighFromRtm(stdplus::raw::asView<char>(msg));
    EXPECT_EQ("192.168.1.20"_ip, ret.addr);
    EXPECT_EQ((ether_addr{1, 2, 3, 4, 5, 6}), ret.mac);
}

} // namespace phosphor::network::netlink
