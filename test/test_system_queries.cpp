#include "system_queries.hpp"
#include "mock_syscall.hpp"
#include <net/if.h>
#include <stdplus/raw.hpp>
#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{
namespace system
{

using stdplus::operator""_sub;

class TestSystemQueries : public testing::Test
{
  public:
    void SetUp() override
    {
        mock_clear();
    }

    void TearDown() override
    {
        mock_clear();
    }
};

TEST_F(TestSystemQueries, GetEthInfoSuccess)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = IFF_UP | IFF_RUNNING, .name = "eth0"});

    auto info = getEthInfo("eth0");

    EXPECT_FALSE(info.autoneg);
    EXPECT_EQ(0, info.speed);
    EXPECT_FALSE(info.fullDuplex);
}

TEST_F(TestSystemQueries, GetEthInfoNonExistentInterface)
{
    auto info = getEthInfo("eth99");

    EXPECT_FALSE(info.autoneg);
    EXPECT_EQ(0, info.speed);
    EXPECT_FALSE(info.fullDuplex);
}

TEST_F(TestSystemQueries, GetEthInfoMultipleInterfaces)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = IFF_UP, .name = "eth0"});
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 2, .flags = IFF_UP, .name = "eth1"});

    auto info0 = getEthInfo("eth0");
    auto info1 = getEthInfo("eth1");

    EXPECT_FALSE(info0.autoneg);
    EXPECT_FALSE(info1.autoneg);
}

TEST_F(TestSystemQueries, SetMTUSuccess)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0", .mtu = 1500});

    EXPECT_NO_THROW(setMTU("eth0", 9000));
}

TEST_F(TestSystemQueries, SetMTUStandardValues)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setMTU("eth0", 1500));  // Standard Ethernet
    EXPECT_NO_THROW(setMTU("eth0", 9000));  // Jumbo frames
    EXPECT_NO_THROW(setMTU("eth0", 1280));  // IPv6 minimum
}

TEST_F(TestSystemQueries, SetMTUNonExistentInterface)
{
    EXPECT_THROW(setMTU("eth99", 1500), std::system_error);
}

TEST_F(TestSystemQueries, SetNICUpSuccess)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setNICUp("eth0", true));
}

TEST_F(TestSystemQueries, SetNICDownSuccess)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = IFF_UP, .name = "eth0"});

    EXPECT_NO_THROW(setNICUp("eth0", false));
}

TEST_F(TestSystemQueries, SetNICUpAlreadyUp)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = IFF_UP, .name = "eth0"});

    EXPECT_NO_THROW(setNICUp("eth0", true));
}

TEST_F(TestSystemQueries, SetNICDownAlreadyDown)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setNICUp("eth0", false));
}

TEST_F(TestSystemQueries, SetNICUpNonExistentInterface)
{
    EXPECT_THROW(setNICUp("eth99", true), std::system_error);
}

TEST_F(TestSystemQueries, SetNICStateMultipleInterfaces)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 2, .flags = 0, .name = "eth1"});

    EXPECT_NO_THROW(setNICUp("eth0", true));
    EXPECT_NO_THROW(setNICUp("eth1", true));
}

TEST_F(TestSystemQueries, DeleteInterfaceSuccess)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 2, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(deleteIntf(2));
}

TEST_F(TestSystemQueries, DeleteInterfaceZeroIndex)
{
    EXPECT_NO_THROW(deleteIntf(0));
}

TEST_F(TestSystemQueries, DeleteInterfaceNonExistent)
{
    EXPECT_THROW(deleteIntf(999), std::runtime_error);
}

TEST_F(TestSystemQueries, DeleteMultipleInterfaces)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 2, .flags = 0, .name = "eth0"});
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 3, .flags = 0, .name = "eth1"});

    EXPECT_NO_THROW(deleteIntf(2));
    EXPECT_NO_THROW(deleteIntf(3));
}

TEST_F(TestSystemQueries, DeleteLinkLocalIPv4Success)
{
    auto addr = "169.254.1.1/16"_sub;
    bool result = deleteLinkLocalIPv4ViaNetlink(1, addr);

    EXPECT_TRUE(result);
}

TEST_F(TestSystemQueries, DeleteLinkLocalIPv4DifferentPrefix)
{
    auto addr = "169.254.100.50/24"_sub;
    bool result = deleteLinkLocalIPv4ViaNetlink(1, addr);

    EXPECT_TRUE(result);
}

TEST_F(TestSystemQueries, DeleteNonLinkLocalIPv4)
{
    auto addr = "192.168.1.10/24"_sub;
    bool result = deleteLinkLocalIPv4ViaNetlink(1, addr);

    EXPECT_FALSE(result);
}

TEST_F(TestSystemQueries, DeleteLinkLocalIPv4PrivateNetwork)
{
    auto addr = "10.0.0.1/8"_sub;
    bool result = deleteLinkLocalIPv4ViaNetlink(1, addr);

    EXPECT_FALSE(result);
}

TEST_F(TestSystemQueries, DeleteLinkLocalIPv6NotAffected)
{
    auto addr = "fe80::1/64"_sub;
    bool result = deleteLinkLocalIPv4ViaNetlink(1, addr);

    EXPECT_FALSE(result);
}

TEST_F(TestSystemQueries, DeleteLinkLocalIPv4BoundaryAddresses)
{
    auto addr1 = "169.254.0.0/16"_sub;
    auto addr2 = "169.254.255.255/16"_sub;

    EXPECT_TRUE(deleteLinkLocalIPv4ViaNetlink(1, addr1));
    EXPECT_TRUE(deleteLinkLocalIPv4ViaNetlink(1, addr2));
}

TEST_F(TestSystemQueries, DeleteLinkLocalIPv4JustOutsideRange)
{
    auto addr1 = "169.253.255.255/16"_sub;
    auto addr2 = "169.255.0.0/16"_sub;

    EXPECT_FALSE(deleteLinkLocalIPv4ViaNetlink(1, addr1));
    EXPECT_FALSE(deleteLinkLocalIPv4ViaNetlink(1, addr2));
}

TEST_F(TestSystemQueries, SetMTUAndBringUp)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setMTU("eth0", 9000));
    EXPECT_NO_THROW(setNICUp("eth0", true));
}

TEST_F(TestSystemQueries, BringUpSetMTUBringDown)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setNICUp("eth0", true));
    EXPECT_NO_THROW(setMTU("eth0", 1500));
    EXPECT_NO_THROW(setNICUp("eth0", false));
}

TEST_F(TestSystemQueries, EmptyInterfaceName)
{
    EXPECT_THROW(setNICUp("", true), std::system_error);
}

TEST_F(TestSystemQueries, VeryLongInterfaceName)
{
    std::string longName(IFNAMSIZ + 10, 'a');
    EXPECT_THROW(setNICUp(longName, true), std::system_error);
}

TEST_F(TestSystemQueries, InterfaceNameExactlyIFNAMSIZ)
{
    std::string maxName(IFNAMSIZ - 1, 'a');
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = maxName});

    EXPECT_NO_THROW(setNICUp(maxName, true));
}

TEST_F(TestSystemQueries, SetMTUZero)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setMTU("eth0", 0));
}

TEST_F(TestSystemQueries, SetMTUVeryLarge)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setMTU("eth0", 65535));
}

TEST_F(TestSystemQueries, MultipleOperationsSameInterface)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    EXPECT_NO_THROW(setMTU("eth0", 1500));
    EXPECT_NO_THROW(setNICUp("eth0", true));
    EXPECT_NO_THROW(setMTU("eth0", 9000));
    EXPECT_NO_THROW(setNICUp("eth0", false));
    EXPECT_NO_THROW(setNICUp("eth0", true));
}

TEST_F(TestSystemQueries, DifferentInterfaceTypes)
{
    mock_addIF(InterfaceInfo{
        .type = ARPHRD_ETHER, .idx = 1, .flags = 0, .name = "eth0"});
    mock_addIF(InterfaceInfo{
        .type = ARPHRD_LOOPBACK, .idx = 2, .flags = 0, .name = "lo"});

    EXPECT_NO_THROW(setNICUp("eth0", true));
    EXPECT_NO_THROW(setNICUp("lo", true));
}

TEST_F(TestSystemQueries, ManyInterfaces)
{
    for (int i = 0; i < 100; ++i)
    {
        mock_addIF(InterfaceInfo{.type = 1,
                                 .idx = static_cast<unsigned>(i + 1),
                                 .flags = 0,
                                 .name = "eth" + std::to_string(i)});
    }

    EXPECT_NO_THROW(setNICUp("eth0", true));
    EXPECT_NO_THROW(setNICUp("eth50", true));
    EXPECT_NO_THROW(setNICUp("eth99", true));
}

TEST_F(TestSystemQueries, RapidStateChanges)
{
    mock_addIF(InterfaceInfo{
        .type = 1, .idx = 1, .flags = 0, .name = "eth0"});

    for (int i = 0; i < 10; ++i)
    {
        EXPECT_NO_THROW(setNICUp("eth0", true));
        EXPECT_NO_THROW(setNICUp("eth0", false));
    }
}

} // namespace system
} // namespace network
} // namespace phosphor
