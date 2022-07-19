#include "hyp_ethernet_interface.hpp"

class HypEthInterface;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

// The total number of vmi attributes defined in biosTableAttrs
// currently is 9:
// 4 attributes of interface 0
// 4 attributes of interface 1
// and 1 vmi_hostname attribute
constexpr auto BIOS_ATTRS_SIZE = 9;

void HypEthInterface::setIpPropsInMap(
    std::string attrName, std::variant<std::string, int64_t> attrValue,
    std::string attrType)
{
    manager.setBIOSTableAttr(attrName, attrValue, attrType);
}

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.getBIOSTableAttrs();
}

void HypEthInterface::updateIPAddress(std::string ip, std::string updatedIp)
{
    auto it = addrs.find(ip);
    if (it != addrs.end())
    {
        auto& ipObj = it->second;

        // Delete the ip address from the local copy (addrs)
        // and update it with the new ip and ip address object
        if (deleteObject(ip))
        {
            addrs.emplace(updatedIp, std::move(ipObj));
            log<level::INFO>("Successfully updated ip address");
            return;
        }
        log<level::ERR>("Updation of ip address not successful");
        return;
    }
}

bool HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        log<level::ERR>("DeleteObject:Unable to find the object.");
        return false;
    }
    addrs.erase(it);
    log<level::INFO>("Successfully deleted the ip address object");
    return true;
}

std::string HypEthInterface::getIntfLabel()
{
    // This method returns if0/if1 based on the eth
    // interface label eth0/eth1 in the object path
    const std::string ethIntfLabel =
        objectPath.substr(objectPath.rfind("/") + 1);
    if (ethIntfLabel == "eth0")
    {
        return "if0";
    }
    else if (ethIntfLabel == "eth1")
    {
        return "if1";
    }
    return "";
}

void HypEthInterface::createIPAddressObjects()
{
    // Access the biosTableAttrs of the parent object to create the ip address
    // object
    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
        return;
    }
    std::string ipAddr;
    HypIP::Protocol ipProtocol;
    HypIP::AddressOrigin ipOrigin;
    uint8_t ipPrefixLength;
    std::string ipGateway;

    auto biosTableAttrs = manager.getBIOSTableAttrs();

    if (biosTableAttrs.size() < BIOS_ATTRS_SIZE)
    {
        log<level::INFO>("Creating ip address object with default values");
        if (intfLabel == "if0")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth0", std::make_unique<HypIPAddress>(
                                      bus, (objectPath + "/ipv4/addr0").c_str(),
                                      *this, HypIP::Protocol::IPv4, "0.0.0.0",
                                      HypIP::AddressOrigin::Static, 0,
                                      "0.0.0.0", intfLabel));
        }
        else if (intfLabel == "if1")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth1", std::make_unique<HypIPAddress>(
                                      bus, (objectPath + "/ipv4/addr0").c_str(),
                                      *this, HypIP::Protocol::IPv4, "0.0.0.0",
                                      HypIP::AddressOrigin::Static, 0,
                                      "0.0.0.0", intfLabel));
        }
        return;
    }

    for (std::string protocol : {"ipv4", "ipv6"})
    {
        std::string vmi_prefix = "vmi_" + intfLabel + "_" + protocol + "_";

        auto biosTableItr = biosTableAttrs.find(vmi_prefix + "method");
        if (biosTableItr != biosTableAttrs.end())
        {
            std::string ipType = std::get<std::string>(biosTableItr->second);
            if (ipType.find("Static") != std::string::npos)
            {
                ipOrigin = HypIP::AddressOrigin::Static;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    dhcp4(false);
                }
                else if (protocol == "ipv6")
                {
                    dhcp6(false);
                }
            }
            else if (ipType.find("DHCP") != std::string::npos)
            {
                ipOrigin = HypIP::AddressOrigin::DHCP;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    dhcp4(true);
                }
                else if (protocol == "ipv6")
                {
                    dhcp6(true);
                }
            }
            else
            {
                log<level::ERR>("Error - Neither Static/DHCP");
            }
        }
        else
        {
            continue;
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "ipaddr");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipAddr = std::get<std::string>(biosTableItr->second);
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "prefix_length");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipPrefixLength =
                static_cast<uint8_t>(std::get<int64_t>(biosTableItr->second));
        }

        biosTableItr = biosTableAttrs.find(vmi_prefix + "gateway");
        if (biosTableItr != biosTableAttrs.end())
        {
            ipGateway = std::get<std::string>(biosTableItr->second);
        }

        std::string ipObjId = "addr0";
        if (protocol == "ipv4")
        {
            ipProtocol = HypIP::Protocol::IPv4;
        }
        else if (protocol == "ipv6")
        {
            ipProtocol = HypIP::Protocol::IPv6;
        }

        addrs.emplace(ipAddr,
                      std::make_unique<HypIPAddress>(
                          bus,
                          (objectPath + "/" + protocol + "/" + ipObjId).c_str(),
                          *this, ipProtocol, ipAddr, ipOrigin, ipPrefixLength,
                          ipGateway, intfLabel));
    }
}

bool HypEthInterface::ipv6AcceptRA(bool value)
{
    auto currValue = ipv6AcceptRA();
    if (currValue != value)
    {
        HypEthernetIntf::ipv6AcceptRA(value);
    }
    return value;
}

bool HypEthInterface::dhcp4(bool value)
{
    auto currValue = dhcp4();
    if (currValue != value)
    {
        HypEthernetIntf::dhcp4(value);
    }
    return value;
}

bool HypEthInterface::dhcp6(bool value)
{
    auto currValue = dhcp6();
    if (currValue != value)
    {
        HypEthernetIntf::dhcp6(value);
    }
    return value;
}

bool HypEthInterface::dhcpIsEnabled(HypIP::Protocol family)
{
    switch (family)
    {
        case HypIP::Protocol::IPv6:
            return dhcp6();
        case HypIP::Protocol::IPv4:
            return dhcp4();
    }
    throw std::logic_error("Unreachable");
}

HypEthInterface::DHCPConf HypEthInterface::dhcpEnabled(DHCPConf value)
{
    auto old4 = HypEthernetIntf::dhcp4();
    auto new4 = HypEthernetIntf::dhcp4(value == DHCPConf::v4 ||
                                       value == DHCPConf::v4v6stateless ||
                                       value == DHCPConf::both);
    auto old6 = HypEthernetIntf::dhcp6();
    auto new6 = HypEthernetIntf::dhcp6(value == DHCPConf::v6 ||
                                       value == DHCPConf::both);
    auto oldra = HypEthernetIntf::ipv6AcceptRA();
    auto newra = HypEthernetIntf::ipv6AcceptRA(
        value == DHCPConf::v6stateless || value == DHCPConf::v4v6stateless ||
        value == DHCPConf::v6 || value == DHCPConf::both);

    if (old4 != new4 || old6 != new6 || oldra != newra)
    {
        HypEthernetIntf::dhcpEnabled(value);
    }

    return value;
}

HypEthInterface::DHCPConf HypEthInterface::dhcpEnabled() const
{
    if (dhcp6())
    {
        return dhcp4() ? DHCPConf::both : DHCPConf::v6;
    }
    else if (dhcp4())
    {
        return ipv6AcceptRA() ? DHCPConf::v4v6stateless : DHCPConf::v4;
    }
    return ipv6AcceptRA() ? DHCPConf::v6stateless : DHCPConf::none;
}

} // namespace network
} // namespace phosphor
