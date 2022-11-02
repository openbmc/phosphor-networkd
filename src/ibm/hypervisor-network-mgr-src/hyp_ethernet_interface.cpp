#include "hyp_ethernet_interface.hpp"

class HypEthInterface;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using BIOSConfigManager =
    sdbusplus::xyz::openbmc_project::BIOSConfig::server::Manager;

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

ObjectPath HypEthInterface::ip(HypIP::Protocol protType, std::string ipaddress,
                               uint8_t prefixLength, std::string gateway)
{
    if (dhcpIsEnabled(protType))
    {
        log<level::INFO>("Disabling DHCP on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        switch (protType)
        {
            case HypIP::Protocol::IPv4:
                dhcp4(false);
                break;
            case HypIP::Protocol::IPv6:
                dhcp6(false);
                break;
        }
    }

    HypIP::AddressOrigin origin = HypIP::AddressOrigin::Static;

    InAddrAny addr;
    try
    {
        switch (protType)
        {
            case HypIP::Protocol::IPv4:
                addr = ToAddr<in_addr>{}(ipaddress);
                break;
            case HypIP::Protocol::IPv6:
                addr = ToAddr<in6_addr>{}(ipaddress);
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
        if (!validUnicast(addr))
        {
            throw std::invalid_argument("not unicast");
        }
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Invalid IP `{}`: {}\n", ipaddress, e.what());
        log<level::ERR>(msg.c_str(), entry("ADDRESS=%s", ipaddress.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }
    IfAddr ifaddr;
    try
    {
        ifaddr = {addr, prefixLength};
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Invalid prefix length `{}`: {}\n", prefixLength,
                               e.what());
        log<level::ERR>(msg.c_str(),
                        entry("PREFIXLENGTH=%" PRIu8, prefixLength));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
    }

    try
    {
        if (!gateway.empty() && protType == HypIP::Protocol::IPv4)
        {
            gateway = std::to_string(ToAddr<in_addr>{}(gateway));
        }
    }
    catch (const std::exception& e)
    {
        auto msg = fmt::format("Invalid v4 GW `{}`: {}", gateway, e.what());
        log<level::ERR>(msg.c_str(), entry("GATEWAY=%s", gateway.c_str()));
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
        return sdbusplus::message::details::string_path_wrapper();
    }

    const std::string ipObjId = "addr0";
    std::string protocol;
    std::string biosMethod;
    if (protType == HypIP::Protocol::IPv4)
    {
        protocol = "ipv4";
        biosMethod = "IPv4Static";
    }
    else if (protType == HypIP::Protocol::IPv6)
    {
        protocol = "ipv6";
        biosMethod = "IPv6Static";
    }

    std::string objPath = objectPath + "/" + protocol + "/" + ipObjId;

    for (auto& addr : addrs)
    {
        auto& ipObj = addr.second;

        if (ipObj->type() != protType)
        {
            continue;
        }

        std::string ipObjAddr = ipObj->address();
        uint8_t ipObjPrefixLen = ipObj->prefixLength();
        std::string ipObjGateway = ipObj->gateway();

        if ((ipaddress == ipObjAddr) && (prefixLength == ipObjPrefixLen) &&
            (gateway == ipObjGateway))
        {
            log<level::INFO>("Trying to set same IP properties");
        }
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        break;
    }

    log<level::INFO>("Updating IP properties",
                     entry("OBJPATH=%s", objPath.c_str()),
                     entry("INTERFACE=%s", intfLabel.c_str()),
                     entry("ADDRESS=%s", ipaddress.c_str()),
                     entry("GATEWAY=%s", gateway.c_str()),
                     entry("PREFIXLENGTH=%d", prefixLength));

    addrs[ipaddress] = std::make_unique<HypIPAddress>(
        bus, (objPath).c_str(), *this, protType, ipaddress, origin,
        prefixLength, gateway, intfLabel);

    PendingAttributesType pendingAttributes;

    auto& ipObj = addrs[ipaddress];

    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("origin"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::Enumeration),
                        biosMethod));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("address"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::String),
                        ipaddress));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("gateway"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::String),
                        gateway));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("prefixLength"),
        std::make_tuple(BIOSConfigManager::convertAttributeTypeToString(
                            BIOSConfigManager::AttributeType::Integer),
                        prefixLength));

    ipObj->updateBiosPendingAttrs(pendingAttributes);

    return objPath;
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

    if (old4 == new4 || old6 == new6 || oldra == newra)
    {
        // if new value is the same as old value
        return value;
    }

    std::unique_ptr<HypIPAddress> ipObj;
    std::string method;

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        bool v4Enabled = false;
        bool v6Enabled = false;
        HypEthernetIntf::DHCPConf newValue;

        if (value == HypEthernetIntf::DHCPConf::v4)
        {
            if ((old4 == false && old6 == false && oldra == false) || old4)
            {
                newValue = value;
                v4Enabled = true;
                v6Enabled = false;
            }
            else if ((old4 == true && old6 == true) || old6)
            {
                newValue = HypEthernetIntf::DHCPConf::both;
                v4Enabled = true;
                v6Enabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::v6)
        {
            if ((old4 == false && old6 == false && oldra == false) ||
                (old4 == true && old6 == true) || oldra || old6)
            {
                newValue = value;
                v4Enabled = false;
                v6Enabled = true;
            }
            else
            {
                newValue = HypEthernetIntf::DHCPConf::both;
                v4Enabled = true;
                v6Enabled = true;
            }
        }
        else if (value == HypEthernetIntf::DHCPConf::both)
        {
            newValue = HypEthernetIntf::DHCPConf::both;
            v4Enabled = true;
            v6Enabled = true;
        }

        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(newValue);

        PendingAttributesType pendingAttributes;
        ipAddrMapType::iterator itr = addrs.begin();
        while (itr != addrs.end())
        {
	    ipObj = std::move(itr.second);
            std::string method;
            if (ipObj->type() == HypIP::Protocol::IPv4)
            {
                if (v4Enabled)
                {
                    method = "IPv4DHCP";
                    ipObj->origin(HypIP::AddressOrigin::DHCP);
                }
                else
                {
                    method = "IPv4Static";
                    // Reset IPv4 to the defaults only when dhcpv4 is disabled;
                    // if the old4 is false (which means static), then
                    // reset shouldn't happen in order to restore the static
                    // v4 configuration
                    if (old4 == true)
                    {
                        ipObj->resetBaseBiosTableAttrs("IPv4");
                    }
                }
            }
            else if (ipObj->type() == HypIP::Protocol::IPv6)
            {
                if (v6Enabled)
                {
                    method = "IPv6DHCP";
                    ipObj->origin(HypIP::AddressOrigin::DHCP);
                }
                else
                {
                    method = "IPv6Static";
                    // Reset IPv6 to the defaults only when dhcpv6 is disabled;
                    // if old6/oldra is false (which means static), then
                    // reset shouldn't happen in order to restore the static
                    // v6 configuration
                    if (old6 == true || oldra == true)
                    {
                        ipObj->resetBaseBiosTableAttrs("IPv6");
                    }
                }
            }
            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    ipObj->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }

            if (std::next(itr) == addrs.end())
            {
                break;
            }
            itr++;
        }
        ipObj->updateBiosPendingAttrs(pendingAttributes);
    }
    else
    {
        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(HypEthernetIntf::DHCPConf::none);

        PendingAttributesType pendingAttributes;
        ipAddrMapType::iterator itr = addrs.begin();
        while (itr != addrs.end())
        {
            ipObj = std::move(itr.second);
            std::string method;

            if ((ipObj->type() == HypIP::Protocol::IPv4) &&
                (ipObj->origin() == HypIP::AddressOrigin::DHCP))
            {
                method = "IPv4Static";
                ipObj->origin(HypIP::AddressOrigin::Static);
                ipObj->resetBaseBiosTableAttrs("IPv4");
            }
            else if ((ipObj->type() == HypIP::Protocol::IPv6) &&
                     (ipObj->origin() == HypIP::AddressOrigin::DHCP))
            {
                method = "IPv6Static";
                ipObj->origin(HypIP::AddressOrigin::Static);
                ipObj->resetBaseBiosTableAttrs("IPv6");
            }

            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    ipObj->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }

            if (std::next(itr) == addrs.end())
            {
                break;
            }
            itr++;
        }
        ipObj->updateBiosPendingAttrs(pendingAttributes);
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
