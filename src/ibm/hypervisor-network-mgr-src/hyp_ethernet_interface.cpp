#include "hyp_ethernet_interface.hpp"

class HypEthInterface;
class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

constexpr char IP_INTERFACE[] = "xyz.openbmc_project.Network.IP";

constexpr char biosStrType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.String";
constexpr char biosIntType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Integer";
constexpr char biosEnumType[] =
    "xyz.openbmc_project.BIOSConfig.Manager.AttributeType.Enumeration";

biosTableRetAttrValueType
    HypEthInterface::getAttrFromBiosTable(const std::string& attrName)
{
    constexpr auto BIOS_SERVICE = "xyz.openbmc_project.BIOSConfigManager";
    constexpr auto BIOS_OBJPATH = "/xyz/openbmc_project/bios_config/manager";
    constexpr auto BIOS_MGR_INTF = "xyz.openbmc_project.BIOSConfig.Manager";

    try
    {
        using getAttrRetType =
            std::tuple<std::string, std::variant<std::string, int64_t>,
                       std::variant<std::string, int64_t>>;
        getAttrRetType ip;
        auto method = bus.new_method_call(BIOS_SERVICE, BIOS_OBJPATH,
                                          BIOS_MGR_INTF, "GetAttribute");

        method.append(attrName);

        auto reply = bus.call(method);

        std::string type;
        std::variant<std::string, int64_t> currValue;
        std::variant<std::string, int64_t> defValue;
        reply.read(type, currValue, defValue);
        return currValue;
    }
    catch (const sdbusplus::exception::SdBusError& ex)
    {
        log<level::ERR>("Failed to get the attribute value from bios table",
                        entry("ERR=%s", ex.what()));
    }
    return "";
}

std::shared_ptr<phosphor::network::HypIPAddress>
    HypEthInterface::getIPAddrObject(std::string attrName,
                                     std::string oldIpAddr = "")
{
    auto biosTableAttrs = manager.getBIOSTableAttrs();
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr == biosTableAttrs.end())
    {
        log<level::ERR>("Attribute not found in the list");
        return NULL;
    }

    std::map<std::string, std::shared_ptr<HypIPAddress>>::iterator findIp;
    if (oldIpAddr != "")
    {
        findIp = addrs.find(oldIpAddr);
    }
    else
    {
        findIp = addrs.find(std::get<std::string>(findAttr->second));
    }
    if (findIp == addrs.end())
    {
        log<level::ERR>("No corresponding ip address object found!");
        return NULL;
    }
    return findIp->second;
}

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

void HypEthInterface::setBiosPropInDbus(
    std::shared_ptr<phosphor::network::HypIPAddress> ipObj,
    std::string attrName, std::variant<std::string, uint8_t> attrValue)
{
    std::string ipObjectPath = ipObj->getObjPath();

    if (attrName == "PrefixLength")
    {
        ipObj->prefixLength(std::get<uint8_t>(attrValue));
    }
    else if (attrName == "Gateway")
    {
        ipObj->gateway(std::get<std::string>(attrValue));
    }
    else if (attrName == "Address")
    {
        ipObj->address(std::get<std::string>(attrValue));
    }
    else if (attrName == "Origin")
    {
        std::string method = std::get<std::string>(attrValue);
        if (method == "IPv4Static")
        {
            ipObj->origin(HypIP::AddressOrigin::Static);
        }
        if (method == "IPv4DHCP")
        {
            ipObj->origin(HypIP::AddressOrigin::DHCP);
        }
    }
}

void HypEthInterface::updateIPAddress(std::string ip, std::string updatedIp)
{
    auto it = addrs.find(ip);
    if (it != addrs.end())
    {
        auto ipObj = it->second;
        if (deleteObject(ip))
        {
            addrs.emplace(updatedIp, ipObj);
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
    // The bios table attributes will be named in the following format:
    // vmi_if0_ipv4_<attrName>. Hence, this method returns if0/if1
    // based on the eth interface label eth0/eth1 in the object path
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

    // The total number of vmi attributes in biosTableAttrs is 9
    // 4 attributes of interface 0, 4 attributes of interface 1,
    // and vmi_hostname attribute
    if (biosTableAttrs.size() < 9)
    {
        log<level::INFO>("Creating ip address object with default values");
        if (intfLabel == "if0")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth0",
                          std::make_shared<phosphor::network::HypIPAddress>(
                              bus, (objectPath + "/ipv4/addr0").c_str(), *this,
                              IP::Protocol::IPv4, "0.0.0.0",
                              IP::AddressOrigin::Static, 0, "0.0.0.0",
                              intfLabel));
        }
        else if (intfLabel == "if1")
        {
            // set the default values for interface 0 in the local
            // copy of the bios table - biosTableAttrs
            manager.setDefaultBIOSTableAttrsOnIntf(intfLabel);
            addrs.emplace("eth1",
                          std::make_shared<phosphor::network::HypIPAddress>(
                              bus, (objectPath + "/ipv4/addr0").c_str(), *this,
                              IP::Protocol::IPv4, "0.0.0.0",
                              IP::AddressOrigin::Static, 0, "0.0.0.0",
                              intfLabel));
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
                ipOrigin = IP::AddressOrigin::Static;
                // update the dhcp enabled property of the eth interface
                HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::none);
            }
            else if (ipType.find("DHCP") != std::string::npos)
            {
                ipOrigin = IP::AddressOrigin::DHCP;
                // update the dhcp enabled property of the eth interface
                if (protocol == "ipv4")
                {
                    HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v4);
                }
                else if (protocol == "ipv6")
                {
                    HypEthernetIntf::dhcpEnabled(HypEthInterface::DHCPConf::v6);
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
            ipProtocol = IP::Protocol::IPv4;
        }
        else if (protocol == "ipv6")
        {
            ipProtocol = IP::Protocol::IPv6;
        }

        addrs.emplace(ipAddr,
                      std::make_shared<phosphor::network::HypIPAddress>(
                          bus,
                          (objectPath + "/" + protocol + "/" + ipObjId).c_str(),
                          *this, ipProtocol, ipAddr, ipOrigin, ipPrefixLength,
                          ipGateway, intfLabel));
    }
}

void HypEthInterface::disableDHCP(HypIP::Protocol protocol)
{
    DHCPConf dhcpState = HypEthernetIntf::dhcpEnabled();
    if (dhcpState == HypEthInterface::DHCPConf::both)
    {
        if (protocol == HypIP::Protocol::IPv4)
        {
            dhcpEnabled(HypEthInterface::DHCPConf::v6);
        }
        else if (protocol == HypIP::Protocol::IPv6)
        {
            dhcpEnabled(HypEthInterface::DHCPConf::v4);
        }
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v4) &&
             (protocol == HypIP::Protocol::IPv4))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::none);
    }
    else if ((dhcpState == HypEthInterface::DHCPConf::v6) &&
             (protocol == HypIP::Protocol::IPv6))
    {
        dhcpEnabled(HypEthInterface::DHCPConf::none);
    }
}

bool HypEthInterface::isDHCPEnabled(HypIP::Protocol family, bool ignoreProtocol)
{
    return (
        (HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::both) ||
        ((HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::v6) &&
         ((family == HypIP::Protocol::IPv6) || ignoreProtocol)) ||
        ((HypEthernetIntf::dhcpEnabled() == HypEthInterface::DHCPConf::v4) &&
         ((family == HypIP::Protocol::IPv4) || ignoreProtocol)));
}

ObjectPath HypEthInterface::ip(HypIP::Protocol protType, std::string ipaddress,
                               uint8_t prefixLength, std::string gateway)
{
    if (isDHCPEnabled(protType))
    {
        log<level::INFO>("DHCP enabled on the interface"),
            entry("INTERFACE=%s", interfaceName().c_str());
        disableDHCP(protType);
    }

    HypIP::AddressOrigin origin = IP::AddressOrigin::Static;

    if (!isValidIP(AF_INET, ipaddress) && !isValidIP(AF_INET6, ipaddress))
    {
        log<level::ERR>("Not a valid IP address"),
            entry("ADDRESS=%s", ipaddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Address"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
        return sdbusplus::message::details::string_path_wrapper();
    }

    if (!isValidIP(AF_INET, gateway) && !isValidIP(AF_INET6, gateway))
    {
        log<level::ERR>("Not a valid gateway"),
            entry("ADDRESS=%s", ipaddress.c_str());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Gateway"),
                              Argument::ARGUMENT_VALUE(ipaddress.c_str()));
        return sdbusplus::message::details::string_path_wrapper();
    }

    if (!isValidPrefix(AF_INET, prefixLength) &&
        !isValidPrefix(AF_INET6, prefixLength))
    {
        log<level::ERR>("PrefixLength is not correct "),
            entry("PREFIXLENGTH=%" PRIu8, prefixLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("prefixLength"),
            Argument::ARGUMENT_VALUE(std::to_string(prefixLength).c_str()));
        return sdbusplus::message::details::string_path_wrapper();
    }

    const std::string intfLabel = getIntfLabel();
    if (intfLabel == "")
    {
        log<level::ERR>("Wrong interface name");
        return sdbusplus::message::details::string_path_wrapper();
    }

    const std::string ipObjId = "addr0";
    std::string protocol;
    if (protType == IP::Protocol::IPv4)
    {
        protocol = "ipv4";
    }
    else if (protType == IP::Protocol::IPv6)
    {
        protocol = "ipv6";
    }

    std::string objPath = objectPath + "/" + protocol + "/" + ipObjId;

    for (auto addr : addrs)
    {
        auto ipObj = addr.second;
        std::string ipObjAddr = ipObj->address();
        uint8_t ipObjPrefixLen = ipObj->prefixLength();
        std::string ipObjGateway = ipObj->gateway();

        if ((ipaddress == ipObjAddr) && (prefixLength == ipObjPrefixLen) &&
            (gateway == ipObjGateway))
        {
            log<level::INFO>("Trying to set same ip properties");
        }
        auto addrKey = addrs.extract(addr.first);
        addrKey.key() = ipaddress;
        break;
    }

    log<level::INFO>("Updating ip properties",
                     entry("OBJPATH=%s", objPath.c_str()),
                     entry("INTERFACE=%s", intfLabel.c_str()),
                     entry("ADDRESS=%s", ipaddress.c_str()),
                     entry("GATEWAY=%s", gateway.c_str()),
                     entry("PREFIXLENGTH=%d", prefixLength));

    addrs[ipaddress] = std::make_shared<phosphor::network::HypIPAddress>(
        bus, (objPath).c_str(), *this, protType, ipaddress, origin,
        prefixLength, gateway, intfLabel);

    PendingAttributesType pendingAttributes;

    auto ipObj = addrs[ipaddress];
    pendingAttributes.insert_or_assign(ipObj->mapDbusToBiosAttr("address"),
                                       std::make_tuple(biosStrType, ipaddress));
    pendingAttributes.insert_or_assign(ipObj->mapDbusToBiosAttr("gateway"),
                                       std::make_tuple(biosStrType, gateway));
    pendingAttributes.insert_or_assign(
        ipObj->mapDbusToBiosAttr("prefixLength"),
        std::make_tuple(biosIntType, prefixLength));

    ipObj->updateBiosPendingAttrs(pendingAttributes);

    return objPath;
}

HypEthernetIntf::DHCPConf
    HypEthInterface::dhcpEnabled(HypEthernetIntf::DHCPConf value)
{
    if (value == HypEthernetIntf::dhcpEnabled())
    {
        return value;
    }

    HypEthernetIntf::dhcpEnabled(value);

    if (value != HypEthernetIntf::DHCPConf::none)
    {
        for (auto itr : addrs)
        {
            auto ipObj = itr.second;
            PendingAttributesType pendingAttributes;
            pendingAttributes.insert_or_assign(
                ipObj->mapDbusToBiosAttr("origin"),
                std::make_tuple(biosEnumType, "IPv4DHCP"));
            ipObj->updateBiosPendingAttrs(pendingAttributes);
            log<level::INFO>("Updating the ip address properties");
            break;
        }
    }
    else
    {
        for (auto itr : addrs)
        {
            auto ipObj = itr.second;
            PendingAttributesType pendingAttributes;
            pendingAttributes.insert_or_assign(
                ipObj->mapDbusToBiosAttr("origin"),
                std::make_tuple(biosEnumType, "IPv4Static"));
            ipObj->updateBiosPendingAttrs(pendingAttributes);
            ipObj->resetBaseBiosTableAttrs();

            break;
        }
    }

    return value;
}

} // namespace network
} // namespace phosphor
