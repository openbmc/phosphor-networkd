#include "config.h"

#include "hyp_network_manager.hpp"

#include "types.hpp"
#include "util.hpp"

#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <fstream>
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

auto HypNetworkMgr::makeDBusCall(const std::string& objectName,
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

void HypNetworkMgr::setBIOSTableAttrs(
    std::string attrName, std::variant<std::string, int64_t> attrValue,
    std::string attrType)
{
    auto findAttr = biosTableAttrs.find(attrName);
    if (findAttr != biosTableAttrs.end())
    {
        if (attrType == "Integer")
        {
            int64_t value = std::get<int64_t>(attrValue);
            biosTableAttrs.erase(findAttr);
            biosTableAttrs.emplace(attrName, value);
        }
        else if (attrType == "String")
        {
            std::string value = std::get<std::string>(attrValue);
            biosTableAttrs.erase(findAttr);
            biosTableAttrs.emplace(attrName, value);
        }
    }
}

void HypNetworkMgr::setBIOSTableAttrs()
{
    try
    {
        std::variant<BiosBaseTableType> response;
        makeDBusCall("/xyz/openbmc_project/bios_config/manager",
                     "xyz.openbmc_project.BIOSConfig.Manager", "BaseBIOSTable")
            .read(response);

        const BiosBaseTableType* baseBiosTable =
            std::get_if<BiosBaseTableType>(&response);

        if (baseBiosTable == nullptr)
        {
            log<level::ERR>("baseBiosTable == nullptr");
            return;
        }

        for (const BiosBaseTableItemType& item : *baseBiosTable)
        {
            if (boost::starts_with(item.first, "vmi"))
            {
                const std::string& itemType =
                    std::get<biosBaseAttrType>(item.second);

                if (boost::ends_with(itemType, "Integer"))
                {
                    const int64_t* currValue = std::get_if<int64_t>(
                        &std::get<biosBaseCurrValue>(item.second));
                    if (item.first == "vmi_if_count")
                    {
                        intfCount = *currValue;
                    }
                    biosTableAttrs.emplace(item.first, *currValue);
                }
                else
                {
                    const std::string* currValue = std::get_if<std::string>(
                        &std::get<biosBaseCurrValue>(item.second));
                    biosTableAttrs.emplace(item.first, *currValue);
                }
            }
        }
    }
    catch (const SdBusError& e)
    {
        log<level::INFO>("Error in making dbus call");
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
        // create if0 object
        interfaces.emplace("if0",
                           std::make_shared<phosphor::network::HypEthInterface>(
                               bus, (objectPath + "/if0").c_str(), *this));
    }
    else if (intfCount == 2)
    {
        // create if0 and if1 objects
        interfaces.emplace("if0",
                           std::make_shared<phosphor::network::HypEthInterface>(
                               bus, (objectPath + "/if0").c_str(), *this));
        interfaces.emplace("if1",
                           std::make_shared<phosphor::network::HypEthInterface>(
                               bus, (objectPath + "/if1").c_str(), *this));
    }
    else
    {
        log<level::ERR>("More than 2 Interfaces");
        return;
    }
}

/*void CACertMgr::erase(uint32_t entryId)
{
    entries.erase(entryId);
}

void CACertMgr::deleteAll()
{
    auto iter = entries.begin();
    while (iter != entries.end())
    {
        auto& entry = iter->second;
        ++iter;
        entry->delete_();
    }
}*/

} // namespace network
} // namespace phosphor
