#include "system_queries.hpp"

#include <linux/rtnetlink.h>
#include <net/if.h>

#include <stdplus/raw.hpp>

#include <gtest/gtest.h>

using std::literals::string_view_literals::operator""sv;

namespace phosphor::network::system
{
namespace detail
{

TEST(ParseInterface, NotLinkType)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;

    EXPECT_THROW(parseInterface(hdr, ""), std::runtime_error);
}

TEST(ParseInterface, SmallMsg)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    auto data = "1"sv;

    EXPECT_THROW(parseInterface(hdr, data), std::runtime_error);
}

TEST(ParseInterface, NoAttrs)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    struct
    {
        ifinfomsg hdr __attribute__((aligned(NLMSG_ALIGNTO)));
    } msg;
    msg.hdr.ifi_index = 1;
    msg.hdr.ifi_flags = 2;
    auto data = stdplus::raw::asView<char>(msg);

    auto info = parseInterface(hdr, data);
    auto expected = InterfaceInfo{.idx = 1, .flags = 2};
    EXPECT_EQ(info, expected);
}

TEST(ParseInterface, AllAttrs)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
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
    msg.hdr.ifi_index = 1;
    msg.hdr.ifi_flags = 2;
    msg.addr_hdr.rta_type = IFLA_ADDRESS;
    msg.addr_hdr.rta_len = RTA_LENGTH(sizeof(msg.addr));
    msg.name_hdr.rta_type = IFLA_IFNAME;
    msg.name_hdr.rta_len = RTA_LENGTH(sizeof(msg.name));
    msg.mtu_hdr.rta_type = IFLA_MTU;
    msg.mtu_hdr.rta_len = RTA_LENGTH(sizeof(msg.mtu));
    auto data = stdplus::raw::asView<char>(msg);

    auto info = parseInterface(hdr, data);
    auto expected = InterfaceInfo{.idx = 1,
                                  .flags = 2,
                                  .name = "eth0",
                                  .mac = ether_addr{0, 1, 2, 3, 4, 5},
                                  .mtu = 50};
    EXPECT_EQ(info, expected);
}

TEST(ValidateNewAddr, Filtering)
{
    AddressInfo info = {};
    EXPECT_TRUE(validateNewAddr(info, {}));

    info.ifidx = 2;
    EXPECT_TRUE(validateNewAddr(info, {}));
    EXPECT_TRUE(validateNewAddr(info, {.ifidx = 2}));
    EXPECT_FALSE(validateNewAddr(info, {.ifidx = 3}));
}

TEST(ValidateNewNeigh, Filtering)
{
    NeighborInfo info = {};
    EXPECT_TRUE(validateNewNeigh(info, {}));

    info.ifidx = 2;
    EXPECT_TRUE(validateNewNeigh(info, {}));
    EXPECT_TRUE(validateNewNeigh(info, {.ifidx = 2}));
    EXPECT_FALSE(validateNewNeigh(info, {.ifidx = 3}));
}

} // namespace detail
} // namespace phosphor::network::system
