#include "config_parser.hpp"
#include "ipaddress.hpp"
#include "mock_network_manager.hpp"
#include "mock_syscall.hpp"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <exception>
#include <fstream>
#include <sdbusplus/bus.hpp>

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
        interface(bus, "/xyz/openbmc_test/network/test0", false, manager)

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

} // namespace network
} // namespace phosphor
