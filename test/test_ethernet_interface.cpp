#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"
#include "util.hpp"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <fstream>
#include <sdbusplus/bus.hpp>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace phosphor
{
namespace network
{

class TestEthernetInterface : public testing::Test
{
  public:
    sdbusplus::bus::bus bus;
    MockManager manager;
    EthernetInterface interface;
    std::string confDir;
    TestEthernetInterface() :
        bus(sdbusplus::bus::new_default()),
        manager(bus, "/xyz/openbmc_test/network", "/tmp/"),
        interface(makeInterface(bus, manager))

    {
        setConfDir();
    }

    void setConfDir()
    {
        char tmp[] = "/tmp/EthernetInterface.XXXXXX";
        confDir = mkdtemp(tmp);
        manager.setConfDir(confDir);
    }

    ~TestEthernetInterface()
    {
        if (confDir != "")
        {
            fs::remove_all(confDir);
        }
    }

    static EthernetInterface makeInterface(sdbusplus::bus::bus& bus,
                                           MockManager& manager)
    {
        mock_clear();
        mock_addIF("test0", 1);
        return {bus,   "test0", "", "/xyz/openbmc_test/network/test0",
                false, manager};
    }

    int countIPObjects()
    {
        return interface.getAddresses().size();
    }

    bool isIPObjectExist(const std::string& ipaddress)
    {
        auto address = interface.getAddresses().find(ipaddress);
        if (address == interface.getAddresses().end())
        {
            return false;
        }
        return true;
    }

    bool deleteIPObject(const std::string& ipaddress)
    {
        auto address = interface.getAddresses().find(ipaddress);
        if (address == interface.getAddresses().end())
        {
            return false;
        }
        address->second->delete_();
        return true;
    }

    std::string getObjectPath(const std::string& ipaddress, uint8_t subnetMask,
                              const std::string& gateway)
    {
        IP::Protocol addressType = IP::Protocol::IPv4;

        return interface.generateObjectPath(addressType, ipaddress, subnetMask,
                                            gateway);
    }

    void createIPObject(IP::Protocol addressType, const std::string& ipaddress,
                        uint8_t subnetMask, const std::string& gateway)
    {
        interface.iP(addressType, ipaddress, subnetMask, gateway);
    }

    // Validates if the DNS entries have been correctly processed
    void validateResolvFile(ServerList values)
    {
        // Check whether the entries has been written to resolv.conf
        fs::path resolvFile = confDir;
        resolvFile /= "resolv.conf";

        // Passed in "value" is what is read from the config file
        interface.writeDNSEntries(values, resolvFile);
        std::string expectedServers =
            "### Generated manually via dbus settings ###";
        expectedServers +=
            "nameserver 9.1.1.1nameserver 9.2.2.2nameserver 9.3.3.3";

        std::string actualServers{};
        std::fstream stream(resolvFile.string().c_str(), std::fstream::in);
        for (std::string line; std::getline(stream, line);)
        {
            actualServers += line;
        }
        EXPECT_EQ(expectedServers, actualServers);
    }
};

TEST_F(TestEthernetInterface, NoIPaddress)
{
    EXPECT_EQ(countIPObjects(), 0);
}

TEST_F(TestEthernetInterface, AddIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16, "10.10.10.1");
    EXPECT_EQ(true, isIPObjectExist("10.10.10.10"));
}

TEST_F(TestEthernetInterface, AddMultipleAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16, "10.10.10.1");
    createIPObject(addressType, "20.20.20.20", 16, "20.20.20.1");
    EXPECT_EQ(true, isIPObjectExist("10.10.10.10"));
    EXPECT_EQ(true, isIPObjectExist("20.20.20.20"));
}

TEST_F(TestEthernetInterface, DeleteIPAddress)
{
    IP::Protocol addressType = IP::Protocol::IPv4;
    createIPObject(addressType, "10.10.10.10", 16, "10.10.10.1");
    createIPObject(addressType, "20.20.20.20", 16, "20.20.20.1");
    deleteIPObject("10.10.10.10");
    EXPECT_EQ(false, isIPObjectExist("10.10.10.10"));
    EXPECT_EQ(true, isIPObjectExist("20.20.20.20"));
}

TEST_F(TestEthernetInterface, DeleteInvalidIPAddress)
{
    EXPECT_EQ(false, deleteIPObject("10.10.10.10"));
}

TEST_F(TestEthernetInterface, CheckObjectPath)
{
    std::string ipaddress = "10.10.10.10";
    uint8_t prefix = 16;
    std::string gateway = "10.10.10.1";

    std::string expectedObjectPath = "/xyz/openbmc_test/network/test0/ipv4/";
    std::stringstream hexId;

    std::string hashString = ipaddress;
    hashString += std::to_string(prefix);
    hashString += gateway;

    hexId << std::hex << ((std::hash<std::string>{}(hashString)) & 0xFFFFFFFF);
    expectedObjectPath += hexId.str();

    EXPECT_EQ(expectedObjectPath, getObjectPath(ipaddress, prefix, gateway));
}

TEST_F(TestEthernetInterface, addNameServers)
{
    ServerList servers = {"9.1.1.1", "9.2.2.2", "9.3.3.3"};
    interface.nameservers(servers);
    fs::path filePath = confDir;
    filePath /= "00-bmc-test0.network";
    config::Parser parser(filePath.string());
    config::ReturnCode rc = config::ReturnCode::SUCCESS;
    config::ValueList values;
    std::tie(rc, values) = parser.getValues("Network", "DNS");
    EXPECT_EQ(servers, values);

    validateResolvFile(values);
}

TEST_F(TestEthernetInterface, addNTPServers)
{
    ServerList servers = {"10.1.1.1", "10.2.2.2", "10.3.3.3"};
    EXPECT_CALL(manager, restartSystemdUnit(networkdService)).Times(1);
    interface.nTPServers(servers);
    fs::path filePath = confDir;
    filePath /= "00-bmc-test0.network";
    config::Parser parser(filePath.string());
    config::ReturnCode rc = config::ReturnCode::SUCCESS;
    config::ValueList values;
    std::tie(rc, values) = parser.getValues("Network", "NTP");
    EXPECT_EQ(servers, values);
}

namespace detail
{

TEST(ParseInterface, NotLinkType)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWADDR;

    std::vector<InterfaceInfo> info;
    EXPECT_THROW(parseInterface(info, hdr, ""), std::runtime_error);
    EXPECT_EQ(0, info.size());
}

TEST(ParseInterface, SmallMsg)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    std::string data = "1";

    std::vector<InterfaceInfo> info;
    EXPECT_THROW(parseInterface(info, hdr, data), std::runtime_error);
    EXPECT_EQ(0, info.size());
}

TEST(ParseInterface, NoAttrs)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    ifinfomsg msg{};
    msg.ifi_index = 1;
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));

    std::vector<InterfaceInfo> info;
    EXPECT_THROW(parseInterface(info, hdr, data), std::runtime_error);
    EXPECT_EQ(0, info.size());
}

TEST(ParseInterface, NoName)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    ifinfomsg msg{};
    msg.ifi_index = 1;
    ether_addr mac = {{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}};
    rtattr addr{};
    addr.rta_len = RTA_LENGTH(sizeof(mac));
    addr.rta_type = IFLA_ADDRESS;
    char addrbuf[RTA_ALIGN(addr.rta_len)];
    std::memset(addrbuf, '\0', sizeof(addrbuf));
    std::memcpy(addrbuf, &addr, sizeof(addr));
    std::memcpy(RTA_DATA(addrbuf), &mac, sizeof(mac));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&addrbuf), sizeof(addrbuf));

    std::vector<InterfaceInfo> info;
    EXPECT_THROW(parseInterface(info, hdr, data), std::runtime_error);
    EXPECT_EQ(0, info.size());
}

TEST(ParseInterface, NoMAC)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    ifinfomsg msg{};
    msg.ifi_index = 1;
    const char* name = "eth0";
    const size_t namesize = strlen(name) + 1;
    rtattr ifname{};
    ifname.rta_len = RTA_LENGTH(namesize);
    ifname.rta_type = IFLA_IFNAME;
    char ifnamebuf[RTA_ALIGN(ifname.rta_len)];
    std::memset(ifnamebuf, '\0', sizeof(ifnamebuf));
    std::memcpy(ifnamebuf, &ifname, sizeof(ifname));
    std::memcpy(RTA_DATA(ifnamebuf), name, namesize);
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&ifnamebuf), sizeof(ifnamebuf));

    std::vector<InterfaceInfo> info;
    parseInterface(info, hdr, data);
    EXPECT_EQ(1, info.size());
    EXPECT_EQ(msg.ifi_index, info[0].index);
    EXPECT_EQ(name, info[0].name);
    EXPECT_FALSE(info[0].mac);
}

TEST(ParseInterface, FilterLoopback)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    ifinfomsg msg{};
    msg.ifi_index = 1;
    msg.ifi_flags = IFF_LOOPBACK;
    const char* name = "eth0";
    const size_t namesize = strlen(name) + 1;
    rtattr ifname{};
    ifname.rta_len = RTA_LENGTH(namesize);
    ifname.rta_type = IFLA_IFNAME;
    char ifnamebuf[RTA_ALIGN(ifname.rta_len)];
    std::memset(ifnamebuf, '\0', sizeof(ifnamebuf));
    std::memcpy(ifnamebuf, &ifname, sizeof(ifname));
    std::memcpy(RTA_DATA(ifnamebuf), name, namesize);
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&ifnamebuf), sizeof(ifnamebuf));

    std::vector<InterfaceInfo> info;
    parseInterface(info, hdr, data);
    EXPECT_EQ(0, info.size());
}

TEST(ParseInterface, Full)
{
    nlmsghdr hdr{};
    hdr.nlmsg_type = RTM_NEWLINK;
    ifinfomsg msg{};
    msg.ifi_index = 1;
    const char* name = "eth0";
    const size_t namesize = strlen(name) + 1;
    rtattr ifname{};
    ifname.rta_len = RTA_LENGTH(namesize);
    ifname.rta_type = IFLA_IFNAME;
    char ifnamebuf[RTA_ALIGN(ifname.rta_len)];
    std::memset(ifnamebuf, '\0', sizeof(ifnamebuf));
    std::memcpy(ifnamebuf, &ifname, sizeof(ifname));
    std::memcpy(RTA_DATA(ifnamebuf), name, namesize);
    ether_addr mac = {{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}};
    rtattr addr{};
    addr.rta_len = RTA_LENGTH(sizeof(mac));
    addr.rta_type = IFLA_ADDRESS;
    char addrbuf[RTA_ALIGN(addr.rta_len)];
    std::memset(addrbuf, '\0', sizeof(addrbuf));
    std::memcpy(addrbuf, &addr, sizeof(addr));
    std::memcpy(RTA_DATA(addrbuf), &mac, sizeof(mac));
    std::string data;
    data.append(reinterpret_cast<char*>(&msg), sizeof(msg));
    data.append(reinterpret_cast<char*>(&addrbuf), sizeof(addrbuf));
    data.append(reinterpret_cast<char*>(&ifnamebuf), sizeof(ifnamebuf));

    std::vector<InterfaceInfo> info;
    parseInterface(info, hdr, data);
    EXPECT_EQ(1, info.size());
    EXPECT_EQ(msg.ifi_index, info[0].index);
    EXPECT_EQ(name, info[0].name);
    EXPECT_TRUE(info[0].mac);
    EXPECT_TRUE(equal(mac, *info[0].mac));
}

} // namespace detail
} // namespace network
} // namespace phosphor
