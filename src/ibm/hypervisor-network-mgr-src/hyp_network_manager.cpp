#include "hyp_network_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using sdbusplus::exception::SdBusError;

namespace phosphor
{
namespace network
{
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

const std::string intType = "Integer";
const std::string strType = "String";
const std::string enumType = "Enumeration";

using ObjectTree =
    std::map<std::string, std::map<std::string, std::vector<std::string>>>;

auto HypNetworkMgr::getDBusProp(const std::string& objectName,
                                const std::string& interface,
                                const std::string& kw)
{
    auto bus = sdbusplus::bus::new_default();
    auto properties = bus.new_method_call(
        "xyz.openbmc_project.BIOSConfigManager", objectName.c_str(),
        "org.freedesktop.DBus.Properties", "Get");
    properties.append(interface);
    properties.append(kw);
    auto result = bus.call(properties);

    if (result.is_method_error())
    {
        throw std::runtime_error("Get api failed");
    }
    return result;
}

void HypNetworkMgr::setBIOSTableAttr(
    std::string attrName, std::variant<std::string, int64_t> attrValue,
    std::string attrType)
{
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr != biosTableAttrs.end())
    {
        if (attrType == intType)
        {
            int64_t value = std::get<int64_t>(attrValue);
            if (value != std::get<int64_t>(findAttr->second))
            {
                biosTableAttrs.erase(findAttr);
                biosTableAttrs.emplace(attrName, value);
            }
        }
        else if (attrType == strType)
        {
            std::string value = std::get<std::string>(attrValue);
            if (value != std::get<std::string>(findAttr->second))
            {
                biosTableAttrs.erase(findAttr);
                biosTableAttrs.emplace(attrName, value);
            }
        }
    }
    else
    {
        lg2::info("setBIOSTableAttr: Attribute {ATTR_NAME} is not found in "
                  "biosTableAttrs",
                  "ATTR_NAME", attrName);
    }
}

void HypNetworkMgr::setDefaultBIOSTableAttrsOnIntf(const std::string& intf)
{
    biosTableAttrs.emplace("vmi_" + intf + "_ipv4_ipaddr", "0.0.0.0");
    biosTableAttrs.emplace("vmi_" + intf + "_ipv4_gateway", "0.0.0.0");
    biosTableAttrs.emplace("vmi_" + intf + "_ipv4_prefix_length", 0);
    biosTableAttrs.emplace("vmi_" + intf + "_ipv4_method", "IPv4Static");
}

void HypNetworkMgr::setDefaultHostnameInBIOSTableAttrs()
{
    biosTableAttrs.emplace("vmi_hostname", "");
}

void HypNetworkMgr::setBIOSTableAttrs()
{
    try
    {
        constexpr auto biosMgrIntf = "xyz.openbmc_project.BIOSConfig.Manager";
        constexpr auto biosMgrObj = "/xyz/openbmc_project/bios_config";

        constexpr auto mapperBus = "xyz.openbmc_project.ObjectMapper";
        constexpr auto mapperObj = "/xyz/openbmc_project/object_mapper";
        constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";

        std::vector<std::string> interfaces;
        interfaces.emplace_back(biosMgrIntf);
        auto depth = 0;

        auto mapperCall = bus.new_method_call(mapperBus, mapperObj, mapperIntf,
                                              "GetSubTree");

        mapperCall.append(biosMgrObj, depth, interfaces);

        auto mapperReply = bus.call(mapperCall);
        if (mapperReply.is_method_error())
        {
            lg2::error("Error in mapper call");
            elog<InternalFailure>();
        }

        ObjectTree objectTree;
        mapperReply.read(objectTree);

        if (objectTree.empty())
        {
            lg2::error(
                "No Object has implemented the interface {INTERFACE_NAME}",
                "INTERFACE_NAME", biosMgrIntf);
            elog<InternalFailure>();
        }

        std::string objPath;

        if (1 == objectTree.size())
        {
            objPath = objectTree.begin()->first;
        }
        else
        {
            // If there are more than 2 objects, object path must contain the
            // interface name
            for (const auto& object : objectTree)
            {
                lg2::info("{INTERFACE_NAME}", "INTERFACE_NAME", biosMgrIntf);
                lg2::info("{OBJECT}", "OBJECT", object.first);

                if (std::string::npos != object.first.find(biosMgrIntf))
                {
                    objPath = object.first;
                    break;
                }
            }

            if (objPath.empty())
            {
                lg2::error(
                    "Can't find the object for the interface {INTERFACE_NAME}",
                    "INTERFACE_NAME", biosMgrIntf);
                elog<InternalFailure>();
            }
        }

        std::variant<BiosBaseTableType> response;
        getDBusProp(objPath, biosMgrIntf, "BaseBIOSTable").read(response);

        const BiosBaseTableType* baseBiosTable =
            std::get_if<BiosBaseTableType>(&response);

        if (baseBiosTable == nullptr)
        {
            lg2::error("BaseBiosTable is empty. No attributes found!");
            return;
        }

        for (const BiosBaseTableItemType& item : *baseBiosTable)
        {
            if (item.first.rfind("vmi", 0) == 0) // starts with the prefix
            {
                const std::string& itemType =
                    std::get<biosBaseAttrType>(item.second);

                if (itemType.compare(itemType.size() - intType.size(),
                                     intType.size(), intType) == 0)
                {
                    const int64_t* currValue = std::get_if<int64_t>(
                        &std::get<biosBaseCurrValue>(item.second));
                    if (currValue != nullptr)
                    {
                        biosTableAttrs.emplace(item.first, *currValue);
                    }
                }
                else if ((itemType.compare(itemType.size() - strType.size(),
                                           strType.size(), strType) == 0) ||
                         (itemType.compare(itemType.size() - enumType.size(),
                                           enumType.size(), enumType) == 0))
                {
                    const std::string* currValue = std::get_if<std::string>(
                        &std::get<biosBaseCurrValue>(item.second));
                    if (currValue != nullptr)
                    {
                        biosTableAttrs.emplace(item.first, *currValue);
                    }
                }
                else
                {
                    lg2::error("Unsupported datatype: The attribute is of "
                               "unknown type");
                }
            }
        }
    }
    catch (const SdBusError& e)
    {
        lg2::error("Error in making dbus call");
        throw std::runtime_error("DBus call failed");
    }
}

void HypNetworkMgr::createIfObjects()
{
    setBIOSTableAttrs();

    if ((getBIOSTableAttrs()).size() == 0)
    {
        setDefaultHostnameInBIOSTableAttrs();
    }

    // The hypervisor can support maximum of
    // 2 ethernet interfaces. Both eth0/1 objects are
    // created during init time to support the static
    // network configurations on the both.
    // create eth0 and eth1 objects
    lg2::info("Creating eth0 and eth1 objects");
    interfaces.emplace("eth0",
                       std::make_unique<HypEthInterface>(
                           bus, (objectPath + "/eth0").c_str(), "eth0", *this));
    interfaces.emplace("eth1",
                       std::make_unique<HypEthInterface>(
                           bus, (objectPath + "/eth1").c_str(), "eth1", *this));

    // Create ip address objects for each ethernet interface
    interfaces["eth0"]->createIPAddressObjects();
    interfaces["eth1"]->createIPAddressObjects();
}

void HypNetworkMgr::createSysConfObj()
{
    systemConf.reset(nullptr);
    this->systemConf =
        std::make_unique<HypSysConfig>(bus, objectPath + "/config", *this);
}

} // namespace network
} // namespace phosphor
