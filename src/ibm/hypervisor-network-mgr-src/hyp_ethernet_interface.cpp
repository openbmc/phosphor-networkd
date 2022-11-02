#include "hyp_ethernet_interface.hpp"

#include <phosphor-logging/lg2.hpp>

class HypEthInterface;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using BIOSConfigManager =
    sdbusplus::xyz::openbmc_project::BIOSConfig::server::Manager;

constexpr char biosEnumType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration";

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
    manager.get().setBIOSTableAttr(attrName, attrValue, attrType);
}

biosTableType HypEthInterface::getBiosAttrsMap()
{
    return manager.get().getBIOSTableAttrs();
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
            lg2::info("Successfully updated ip address");
            return;
        }
        lg2::error("Updation of ip address not successful");
        return;
    }
}

bool HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        lg2::error("DeleteObject:Unable to find the object.");
        return false;
    }
    addrs.erase(it);
    lg2::info("Successfully deleted the ip address object");
    return true;
}

std::string HypEthInterface::getIntfLabel()
{
    // This method returns if0/if1 based on the eth
    // interface label eth0/eth1 in the object path
    const std::string ethIntfLabel =
        objectPath.str.substr(objectPath.str.rfind("/") + 1);
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
        lg2::error("Wrong interface name");
        return;
    }
    std::string ipAddr;
    HypIP::AddressOrigin ipOrigin;
    uint8_t ipPrefixLength;
    std::string ipGateway;

    auto biosTableAttrs = manager.get().getBIOSTableAttrs();

    if (biosTableAttrs.size() < BIOS_ATTRS_SIZE)
    {
        lg2::info("Creating ip address object with default values");
        std::optional<stdplus::InAnyAddr> addr;
        addr.emplace(stdplus::fromStr<stdplus::In4Addr>("0.0.0.0"));

        std::optional<stdplus::SubnetAny> ifaddr;
        ifaddr.emplace(*addr, 0);
        if (intfLabel == "if0")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth0", std::make_unique<HypIPAddress>(
                                      bus,
                                      sdbusplus::message::object_path(
                                          objectPath.str + "/ipv4/addr0"),
                                      *this, *ifaddr, "0.0.0.0",
                                      HypIP::AddressOrigin::Static, intfLabel));
        }
        else if (intfLabel == "if1")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.get().setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth1", std::make_unique<HypIPAddress>(
                                      bus,
                                      sdbusplus::message::object_path(
                                          objectPath.str + "/ipv4/addr0"),
                                      *this, *ifaddr, "0.0.0.0",
                                      HypIP::AddressOrigin::Static, intfLabel));
        }
        return;
    }

    // Protocol list will be extended to ipv6 in future commit
    for (std::string protocol : {"ipv4"})
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
            }
            else if (ipType.find("DHCP") != std::string::npos)
            {
                ipOrigin = HypIP::AddressOrigin::DHCP;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    dhcp4(true);
                }
            }
            else
            {
                lg2::error("Error - Neither Static/DHCP");
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

        std::optional<stdplus::InAnyAddr> addr;
        try
        {
            if (protocol == "ipv4")
            {
                addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipAddr));
            }
            else
            {
                throw std::logic_error("Exhausted protocols");
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Invalid IP {NET_IP}: {ERROR}", "NET_IP", ipAddr,
                       "ERROR", e);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipAddr"),
                                  Argument::ARGUMENT_VALUE(ipAddr.c_str()));
        }
        std::optional<stdplus::SubnetAny> ifaddr;
        ifaddr.emplace(*addr, ipPrefixLength);
        std::string ipObjId = "addr0";

        addrs.emplace(ipAddr,
                      std::make_unique<HypIPAddress>(
                          bus,
                          sdbusplus::message::object_path(
                              objectPath.str + "/" + protocol + "/" + ipObjId),
                          *this, *ifaddr, ipGateway, ipOrigin, intfLabel));
    }
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

ObjectPath HypEthInterface::ip(HypIP::Protocol protType, std::string ipaddress,
                               uint8_t prefixLength, std::string gateway)
{
    HypIP::AddressOrigin origin = HypIP::AddressOrigin::Static;

    std::optional<stdplus::InAnyAddr> addr;
    try
    {
        lg2::info(
            "Static IP Config: Disabling DHCP on the interface: {INTERFACE}",
            "INTERFACE", interfaceName());
        switch (protType)
        {
            case HypIP::Protocol::IPv4:
                dhcp4(false);
                addr.emplace(stdplus::fromStr<stdplus::In4Addr>(ipaddress));
                break;
            case HypIP::Protocol::IPv6:
                dhcp6(false);
                addr.emplace(stdplus::fromStr<stdplus::In6Addr>(ipaddress));
                break;
            default:
                throw std::logic_error("Exhausted protocols");
        }
        if (!std::visit([](auto ip) { return validIntfIP(ip); }, *addr))
        {
            throw std::invalid_argument("not unicast");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid IP/Protocol {NET_IP}: {ERROR}", "NET_IP", ipaddress,
                   "ERROR", e);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("ipaddress"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
    }

    std::optional<stdplus::SubnetAny> ifaddr;
    try
    {
        if (prefixLength == 0)
        {
            throw std::invalid_argument("default route");
        }
        ifaddr.emplace(*addr, prefixLength);
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid prefix length {NET_PFX}: {ERROR}", "NET_PFX",
                   prefixLength, "ERROR", e);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(stdplus::toStr(prefixLength).c_str()));
    }

    try
    {
        if (!gateway.empty())
        {
            if (protType == HypIP::Protocol::IPv4)
            {
                validateGateway<stdplus::In4Addr>(gateway);
            }
        }
        else
        {
            throw std::invalid_argument("Empty gateway");
        }
    }
    catch (const std::exception& e)
    {
        lg2::error("Invalid Gateway: {GATEWAY}, Error: {ERR}", "GATEWAY",
                   gateway, "ERR", e.what());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("GATEWAY"),
                              Argument::ARGUMENT_VALUE(gateway.c_str()));
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        lg2::error("Wrong interface name");
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

    std::string objPath = objectPath.str + "/" + protocol + "/" + ipObjId;

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
            lg2::info("Trying to set same IP properties");
            return sdbusplus::message::object_path(objPath);
        }
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        break;
    }

    lg2::info(
        "Updating IP properties, ObjectPath: {OBJPATH}, Interface: {INTERFACE}, IP: {ADDRESS}, Gateway: {GATEWAY}, Prefix length: {PREFIXLENGTH}",
        "OBJPATH", objPath, "INTERFACE", intfLabel, "ADDRESS", ipaddress,
        "GATEWAY", gateway, "PREFIXLENGTH", prefixLength);

    addrs[ipaddress] = std::make_unique<HypIPAddress>(
        bus, sdbusplus::message::object_path(objPath), *this, *ifaddr, gateway,
        origin, intfLabel);

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

    return sdbusplus::message::object_path(objPath);
}

HypEthInterface::DHCPConf HypEthInterface::dhcpEnabled(DHCPConf value)
{
    auto old4 = HypEthernetIntf::dhcp4();
    auto new4 = HypEthernetIntf::dhcp4(value == DHCPConf::v4);

    if (old4 == new4)
    {
        // if new value is the same as old value
        return value;
    }

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        HypEthernetIntf::DHCPConf newValue = HypEthernetIntf::DHCPConf::v4;
        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(newValue);
        PendingAttributesType pendingAttributes;
        ipAddrMapType::iterator itr = addrs.begin();
        while (itr != addrs.end())
        {
            std::string method;
            if ((itr->second)->type() == HypIP::Protocol::IPv4)
            {
                method = "IPv4DHCP";
                (itr->second)->origin(HypIP::AddressOrigin::DHCP);
            }
            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    (itr->second)->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }
            if (std::next(itr) == addrs.end())
            {
                break;
            }
            itr++;
        }
        (itr->second)->updateBiosPendingAttrs(pendingAttributes);
    }
    else
    {
        // Set dhcpEnabled value
        HypEthernetIntf::dhcpEnabled(HypEthernetIntf::DHCPConf::none);

        PendingAttributesType pendingAttributes;

        ipAddrMapType::iterator itr = addrs.begin();
        while (itr != addrs.end())
        {
            std::string method;
            if (((itr->second)->type() == HypIP::Protocol::IPv4) &&
                ((itr->second)->origin() == HypIP::AddressOrigin::DHCP))
            {
                method = "IPv4Static";
                (itr->second)->origin(HypIP::AddressOrigin::Static);
                (itr->second)->resetBaseBiosTableAttrs();
            }
            if (!method.empty())
            {
                pendingAttributes.insert_or_assign(
                    (itr->second)->mapDbusToBiosAttr("origin"),
                    std::make_tuple(biosEnumType, method));
            }
            if (std::next(itr) == addrs.end())
            {
                break;
            }
            itr++;
        }
        (itr->second)->updateBiosPendingAttrs(pendingAttributes);
    }

    return value;
}

HypEthInterface::DHCPConf HypEthInterface::dhcpEnabled() const
{
    if (dhcp4())
    {
        return DHCPConf::v4;
    }
    return DHCPConf::none;
}

} // namespace network
} // namespace phosphor
