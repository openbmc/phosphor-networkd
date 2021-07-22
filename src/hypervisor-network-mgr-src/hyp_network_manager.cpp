#include "hyp_network_manager.hpp"

#include "types.hpp"
#include "util.hpp"

#include <boost/algorithm/string.hpp>
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

void HypNetworkMgr::setBIOSTableAttr(
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
                else if (boost::ends_with(itemType, "String") ||
                         boost::ends_with(itemType, "Enumeration"))
                {
                    const std::string* currValue = std::get_if<std::string>(
                        &std::get<biosBaseCurrValue>(item.second));
                    biosTableAttrs.emplace(item.first, *currValue);
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

void HypNetworkMgr::createSysConfObj()
{
    systemConf.reset(nullptr);
    this->systemConf = std::make_unique<phosphor::network::HypSysConfig>(
        bus, objectPath + "/config", *this);
}

} // namespace network
} // namespace phosphor
