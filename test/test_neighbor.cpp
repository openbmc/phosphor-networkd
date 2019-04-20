#include "neighbor.hpp"
#include "util.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{
namespace detail
{

TEST(ParseNeighbor, NotNeighborType)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;

    std::vector<NeighborInfo> neighbors;
    EXPECT_THROW(parseNeighbor(hdr, "", neighbors), std::runtime_error);
    EXPECT_EQ(0, neighbors.size());
}

TEST(ParseNeighbor, SmallMsg)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWNEIGH;
    std::string data = "1";

    std::vector<NeighborInfo> neighbors;
    EXPECT_THROW(parseNeighbor(hdr, data, neighbors), std::runtime_error);
    EXPECT_EQ(0, neighbors.size());
}

TEST(ParseNeighbor, BadIf)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWNEIGH;
    ndmsg msg{};
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));

    std::vector<NeighborInfo> neighbors;
    EXPECT_THROW(parseNeighbor(hdr, data, neighbors), std::system_error);
    EXPECT_EQ(0, neighbors.size());
}

TEST(ParseNeighbor, NoAttrs)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWNEIGH;
    ndmsg msg{};
    msg.ndm_ifindex = if_nametoindex("lo");
    ASSERT_NE(0, msg.ndm_ifindex);
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));

    std::vector<NeighborInfo> neighbors;
    EXPECT_THROW(parseNeighbor(hdr, data, neighbors), std::runtime_error);
    EXPECT_EQ(0, neighbors.size());
}

TEST(ParseNeighbor, NoAddress)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWNEIGH;
    ndmsg msg{};
    msg.ndm_ifindex = if_nametoindex("lo");
    ASSERT_NE(0, msg.ndm_ifindex);
    ether_addr mac = {{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}};
    rtattr lladdr{};
    lladdr.rta_len = RTA_LENGTH(sizeof(mac));
    lladdr.rta_type = NDA_LLADDR;
    char lladdrbuf[RTA_ALIGN(lladdr.rta_len)];
    std::memset(lladdrbuf, '\0', sizeof(lladdrbuf));
    std::memcpy(lladdrbuf, &lladdr, sizeof(lladdr));
    std::memcpy(RTA_DATA(lladdrbuf), &mac, sizeof(mac));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&lladdrbuf), sizeof(lladdrbuf));

    std::vector<NeighborInfo> neighbors;
    EXPECT_THROW(parseNeighbor(hdr, data, neighbors), std::runtime_error);
    EXPECT_EQ(0, neighbors.size());
}

TEST(ParseNeighbor, NoMAC)
{
    constexpr auto ifstr = "lo";
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWNEIGH;
    ndmsg msg{};
    msg.ndm_family = AF_INET;
    msg.ndm_state = NUD_PERMANENT;
    msg.ndm_ifindex = if_nametoindex(ifstr);
    ASSERT_NE(0, msg.ndm_ifindex);
    in_addr addr;
    ASSERT_EQ(1, inet_pton(msg.ndm_family, "192.168.10.1", &addr));
    rtattr dst{};
    dst.rta_len = RTA_LENGTH(sizeof(addr));
    dst.rta_type = NDA_DST;
    char dstbuf[RTA_ALIGN(dst.rta_len)];
    std::memset(dstbuf, '\0', sizeof(dstbuf));
    std::memcpy(dstbuf, &dst, sizeof(dst));
    std::memcpy(RTA_DATA(dstbuf), &addr, sizeof(addr));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&dstbuf), sizeof(dstbuf));

    std::vector<NeighborInfo> neighbors;
    parseNeighbor(hdr, data, neighbors);
    EXPECT_EQ(1, neighbors.size());
    EXPECT_EQ(ifstr, neighbors[0].interface);
    EXPECT_TRUE(neighbors[0].permanent);
    EXPECT_FALSE(neighbors[0].mac);
    EXPECT_TRUE(equal(addr, std::get<in_addr>(neighbors[0].address)));
}

TEST(ParseNeighbor, Full)
{
    constexpr auto ifstr = "lo";
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWNEIGH;
    ndmsg msg{};
    msg.ndm_family = AF_INET6;
    msg.ndm_state = NUD_NOARP;
    msg.ndm_ifindex = if_nametoindex(ifstr);
    ether_addr mac = {{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}};
    rtattr lladdr{};
    lladdr.rta_len = RTA_LENGTH(sizeof(mac));
    lladdr.rta_type = NDA_LLADDR;
    char lladdrbuf[RTA_ALIGN(lladdr.rta_len)];
    std::memset(lladdrbuf, '\0', sizeof(lladdrbuf));
    std::memcpy(lladdrbuf, &lladdr, sizeof(lladdr));
    std::memcpy(RTA_DATA(lladdrbuf), &mac, sizeof(mac));
    in6_addr addr;
    ASSERT_EQ(1, inet_pton(msg.ndm_family, "fd00::1", &addr));
    rtattr dst{};
    dst.rta_len = RTA_LENGTH(sizeof(addr));
    dst.rta_type = NDA_DST;
    char dstbuf[RTA_ALIGN(dst.rta_len)];
    std::memset(dstbuf, '\0', sizeof(dstbuf));
    std::memcpy(dstbuf, &dst, sizeof(dst));
    std::memcpy(RTA_DATA(dstbuf), &addr, sizeof(addr));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&lladdrbuf), sizeof(lladdrbuf));
    data.append(reinterpret_cast<char*>(&dstbuf), sizeof(dstbuf));

    std::vector<NeighborInfo> neighbors;
    parseNeighbor(hdr, data, neighbors);
    EXPECT_EQ(1, neighbors.size());
    EXPECT_EQ(ifstr, neighbors[0].interface);
    EXPECT_FALSE(neighbors[0].permanent);
    EXPECT_TRUE(neighbors[0].mac);
    EXPECT_TRUE(equal(mac, *neighbors[0].mac));
    EXPECT_TRUE(equal(addr, std::get<in6_addr>(neighbors[0].address)));
}

} // namespace detail
} // namespace network
} // namespace phosphor
