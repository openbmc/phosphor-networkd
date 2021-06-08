#include "hyp_ethernet_interface.hpp"

#include <boost/algorithm/string.hpp>

class HypEthInterface;
class HypIPAddress;

namespace phosphor
{
namespace network
{

using namespace phosphor::logging;

constexpr char IP_INTERFACE[] = "xyz.openbmc_project.Network.IP";

std::shared_ptr<phosphor::network::HypIPAddress>
    HypEthInterface::getIPAddrObject(std::string attrName,
                                     std::string oldIpAddr = "")
{
    auto biosTableAttrs = manager.getBIOSTableAttrs();
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr == biosTableAttrs.end())
    {
        log<level::ERR>("Attribute not found in the list");
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
    manager.setBIOSTableAttrs(attrName, attrValue, attrType);
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

void HypEthInterface::watchBaseBiosTable()
{
    auto BIOSAttrUpdate = [&](sdbusplus::message::message& m) {
        std::map<std::string, std::variant<BiosBaseTableType>>
            interfacesProperties;

        log<level::INFO>("Registering watch on BIOS table");
        std::string objName;
        m.read(objName, interfacesProperties);

        auto find = interfacesProperties.find("BaseBIOSTable");
        if (find == interfacesProperties.end())
        {
            log<level::INFO>(
                "BaseBIOSTable property not found. Continuing to listen...");
            return;
        }

        auto biosTableAttrs = manager.getBIOSTableAttrs();
        // Iterate throught the list to find which property has been changed
        const BiosBaseTableType* baseBiosTable =
            std::get_if<BiosBaseTableType>(&(find->second));

        for (const BiosBaseTableItemType& attr : *baseBiosTable)
        {
            std::string attrName = attr.first;
            if (boost::starts_with(attrName, "vmi"))
            {
                // check for the value against the bios attrs table
                // and update the same in both biosattrs and dbus objects

                if (boost::ends_with(attrName, "length") ||
                    boost::ends_with(attrName, "count"))
                {
                    auto findAttr = biosTableAttrs.find(attrName);
                    if (findAttr != biosTableAttrs.end())
                    {
                        const int64_t* attrValue = std::get_if<int64_t>(
                            &std::get<biosBaseCurrValue>(attr.second));
                        if (std::get<int64_t>(findAttr->second) != *attrValue)
                        {
                            manager.setBIOSTableAttrs(attrName, *attrValue,
                                                      "Integer");

                            // get the appropriate ip object by getting the ip
                            // address from the bios table and match it with the
                            // ip address from the "addrs" data member

                            auto prefixItr =
                                boost::algorithm::find_nth(attrName, "_", 2);
                            std::string hypPrefix = std::string(
                                attrName.begin(), prefixItr.begin());
                            hypPrefix.append("_ipaddr");

                            auto ipObj = getIPAddrObject(hypPrefix);
                            if (ipObj != NULL)
                            {
                                if (boost::ends_with(attrName, "length"))
                                {
                                    setBiosPropInDbus(
                                        ipObj, "PrefixLength",
                                        static_cast<uint8_t>(*attrValue));
                                }
                            }
                            break;
                        }
                        continue;
                    }
                }
                else
                {
                    auto findAttr = biosTableAttrs.find(attrName);
                    if (findAttr != biosTableAttrs.end())
                    {
                        const std::string* attrValue = std::get_if<std::string>(
                            &std::get<biosBaseCurrValue>(attr.second));
                        if (std::get<std::string>(findAttr->second) !=
                            *attrValue)
                        {
                            manager.setBIOSTableAttrs(attrName, *attrValue,
                                                      "String");

                            auto prefixItr =
                                boost::algorithm::find_nth(attrName, "_", 2);
                            std::string hypPrefix = std::string(
                                attrName.begin(), prefixItr.begin());
                            hypPrefix.append("_ipaddr");

                            std::shared_ptr<phosphor::network::HypIPAddress>
                                ipObj = NULL;

                            if (boost::ends_with(attrName, "ipaddr"))
                            {
                                ipObj = getIPAddrObject(
                                    hypPrefix,
                                    std::get<std::string>(findAttr->second));
                            }
                            else
                            {
                                ipObj = getIPAddrObject(hypPrefix);
                            }

                            if (ipObj != NULL)
                            {
                                std::string dbusAttrName;
                                if (boost::ends_with(attrName, "ipaddr"))
                                {
                                    dbusAttrName = "Address";
                                }
                                else if (boost::ends_with(attrName, "gateway"))
                                {
                                    dbusAttrName = "Gateway";
                                }
                                else if (boost::ends_with(attrName, "method"))
                                {
                                    dbusAttrName = "Origin";
                                }
                                setBiosPropInDbus(ipObj, dbusAttrName,
                                                  *attrValue);

                                break;
                            }
                        }
                        continue;
                    }
                }
            }
        }
    };

    phosphor::network::matchBIOSAttrUpdate = std::make_unique<
        sdbusplus::bus::match::match>(
        bus,
        "type='signal',member='PropertiesChanged',interface='org.freedesktop."
        "DBus.Properties',arg0namespace='xyz.openbmc_project.BIOSConfig."
        "Manager'",
        BIOSAttrUpdate);
}

void HypEthInterface::updateIPAddress(std::string ip, std::string updatedIp)
{
    auto it = addrs.find(ip);
    if (it != addrs.end())
    {
        auto ipObj = it->second;
        deleteObject(ip);
        addrs.emplace(updatedIp, ipObj);
        log<level::INFO>("Successfully updated ip address");
        return;
    }
}

std::string HypEthInterface::generateId(const std::string& ipaddress,
                                        uint8_t prefixLength,
                                        const std::string& gateway)
{
    std::stringstream hexId;
    std::string hashString = ipaddress;
    hashString += std::to_string(prefixLength);
    hashString += gateway;

    // Only want 8 hex digits.
    hexId << std::hex << ((std::hash<std::string>{}(hashString)) & 0xFFFFFFFF);
    return hexId.str();
}

void HypEthInterface::deleteObject(const std::string& ipaddress)
{
    auto it = addrs.find(ipaddress);
    if (it == addrs.end())
    {
        log<level::ERR>("DeleteObject:Unable to find the object.");
        return;
    }
    addrs.erase(it);
    log<level::INFO>("Successfully deleted the ip address object");
}

void HypEthInterface::deleteAll()
{
    // Reset the basebios table attrs to default
    for (auto addr : addrs)
    {
        (addr.second)->resetBaseBiosTableAttrs();
    }

    // clear all the ip on the interface
    addrs.clear();
    log<level::INFO>("Successfully deleted all the ip address object");
}

void HypEthInterface::createIPAddressObjects()
{
    // Access the biosTableAttrs of the parent object to create the ip address
    // object
    const std::string intfLabel = objectPath.substr(objectPath.rfind("/") + 1);
    std::string ipAddr;
    HypIP::Protocol ipProtocol;
    HypIP::AddressOrigin ipOrigin;
    uint8_t ipPrefixLength;
    std::string ipGateway;

    auto biosTableAttrs = manager.getBIOSTableAttrs();

    for (std::string protocol : {"ipv4", "ipv6"})
    {
        std::string vmi_prefix = "vmi_" + intfLabel + "_" + protocol + "_";

        auto biosTableItr = biosTableAttrs.find(vmi_prefix + "method");
        if (biosTableItr != biosTableAttrs.end())
        {
            std::string ipType = std::get<std::string>(biosTableItr->second);
            if (boost::contains(ipType, "Static"))
            {
                ipOrigin = IP::AddressOrigin::Static;
            }
            else if (boost::contains(ipType, "DHCP"))
            {
                ipOrigin = IP::AddressOrigin::DHCP;
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

        std::string ipObjId = generateId(ipAddr, ipPrefixLength, ipGateway);
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
                          bus, (objectPath + "/" + protocol + "/" + ipObjId).c_str(), *this,
                          ipProtocol, ipAddr, ipOrigin, ipPrefixLength,
                          ipGateway, intfLabel));
    }
}

} // namespace network
} // namespace phosphor
