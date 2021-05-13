#include "hyp_network_manager.hpp"

#include "types.hpp"
#include "util.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using sdbusplus::exception::SdBusError;

class HypNetworkMgr;

namespace phosphor
{
namespace network
{
using namespace phosphor::logging;
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
        log<level::INFO>(
            "setBIOSTableAttr: Attribute is not found in biosTableAttrs"),
            entry("attrName : ", attrName.c_str());
    }
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

        auto mapperCall =
            bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetSubTree");

        mapperCall.append(biosMgrObj, depth, interfaces);

        auto mapperReply = bus.call(mapperCall);
        if (mapperReply.is_method_error())
        {
            log<level::ERR>("Error in mapper call");
            elog<InternalFailure>();
        }

        ObjectTree objectTree;
        mapperReply.read(objectTree);

        if (objectTree.empty())
        {
            log<level::ERR>("No Object has implemented the interface",
                            entry("INTERFACE=%s", biosMgrIntf));
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
            for (auto const& object : objectTree)
            {
                log<level::INFO>("interface", entry("INT=%s", biosMgrIntf));
                log<level::INFO>("object",
                                 entry("OBJ=%s", object.first.c_str()));

                if (std::string::npos != object.first.find(biosMgrIntf))
                {
                    objPath = object.first;
                    break;
                }
            }

            if (objPath.empty())
            {
                log<level::ERR>("Can't find the object for the interface",
                                entry("intfName=%s", biosMgrIntf));
                elog<InternalFailure>();
            }
        }

        std::variant<BiosBaseTableType> response;
        getDBusProp(objPath, biosMgrIntf, "BaseBIOSTable").read(response);

        const BiosBaseTableType* baseBiosTable =
            std::get_if<BiosBaseTableType>(&response);

        if (baseBiosTable == nullptr)
        {
            log<level::ERR>("BaseBiosTable is empty. No attributes found!");
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
                        if (item.first == "vmi_if_count")
                        {
                            intfCount = *currValue;
                        }
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
                    log<level::ERR>("Unsupported datatype: The attribute is of "
                                    "unknown type");
                }
            }
        }
    }
    catch (const SdBusError& e)
    {
        log<level::ERR>("Error in making dbus call");
        throw std::runtime_error("DBus call failed");
    }
}

uint16_t HypNetworkMgr::getIntfCount()
{
    return intfCount;
}

biosTableType HypNetworkMgr::getBIOSTableAttrs()
{
    return biosTableAttrs;
}

void HypNetworkMgr::createIfObjects()
{
    setBIOSTableAttrs();

    if (intfCount == 1)
    {
        // TODO: create eth0 object
        log<level::INFO>("Create eth0 object");
    }
    else if (intfCount == 2)
    {
        // TODO: create eth0 and eth1 objects
        log<level::INFO>("Create eth0 and eth1 objects");
    }
    else
    {
        log<level::ERR>("More than 2 Interfaces");
        return;
    }
}

} // namespace network
} // namespace phosphor
