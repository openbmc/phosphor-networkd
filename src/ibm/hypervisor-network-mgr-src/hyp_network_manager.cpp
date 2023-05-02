#include "hyp_network_manager.hpp"

#include <optional>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <ranges>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

using sdbusplus::exception::SdBusError;
using namespace std;
using namespace std::ranges;
namespace phosphor
{
namespace network
{
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

const std::string intType = "Integer";
const std::string strType = "String";
const std::string enumType = "Enumeration";

auto getDefaultTable(const std::string& protocol)
{
    static std::array<std::pair<const char*, biosAttrCurrValue>, 4>
        ipv4_defaults = {std::pair<const char*, biosAttrCurrValue>{
                             "_ipv4_ipaddr", biosAttrCurrValue("0.0.0.0"s)},
                         {"_ipv4_gateway", biosAttrCurrValue("0.0.0.0"s)},
                         {"_ipv4_prefix_length", biosAttrCurrValue(0)},
                         {"_ipv4_method", biosAttrCurrValue("IPv4Static"s)}};

    static std::array<std::pair<const char*, biosAttrCurrValue>, 4>
        ipv6_defaults = {std::pair<const char*, biosAttrCurrValue>{
                             "_ipv6_ipaddr", biosAttrCurrValue("::"s)},
                         {"_ipv6_gateway", biosAttrCurrValue("::"s)},
                         {"_ipv6_prefix_length", biosAttrCurrValue(128)},
                         {"_ipv6_method", biosAttrCurrValue("IPv6Static"s)}};
    return (protocol == std::string("ipv4"s)) ? ipv4_defaults : ipv6_defaults;
}

auto getDefaultBIOSTableAttrsOnIntf(const std::string& intf,
                                    const std::string& protocol, auto ins)
{
    std::map<biosAttrName, biosAttrCurrValue> defaults;
    auto d = getDefaultTable(protocol) | views::transform([&](auto& p) {
                 return std::make_pair("vmi_" + intf + p.first, p.second);
             });
    ranges::copy(d, ins);
}
auto setBIOSTableAttrImpl(
    std::map<biosAttrName, biosAttrCurrValue>& biosTableAttrs,
    std::string attrName, const biosAttrCurrValue& attrValue,
    std::string attrType)
{
    using MapType = std::decay_t<decltype(biosTableAttrs)>;
    auto updated = biosTableAttrs |
                   views::transform([&](const auto& p) -> MapType::value_type {
                       if (p.first == attrName)
                       {
                           if (p.second != attrValue)
                           {
                               return std::make_pair(p.first, attrValue);
                           }
                       }
                       return p;
                   });
    biosTableAttrs = MapType(updated.begin(), updated.end());
}

using ObjectTree =
    std::map<std::string, std::map<std::string, std::vector<std::string>>>;
optional<biosTableType::value_type> convert(auto&& item)
{
    auto itemType = std::get<0>(item.second);
    if (itemType == intType)
    {
        const int64_t* currValue =
            std::get_if<int64_t>(&std::get<biosBaseCurrValue>(item.second));
        if (currValue != nullptr)
        {
            return biosTableType::value_type{item.first,
                                             biosAttrCurrValue(*currValue)};
        }
        return nullopt;
    }
    if (itemType == enumType || itemType == strType)
    {
        const std::string* currValue =
            std::get_if<std::string>(&std::get<biosBaseCurrValue>(item.second));
        if (currValue != nullptr)
        {
            return biosTableType::value_type{item.first,
                                             biosAttrCurrValue(*currValue)};
        }
    }
    return nullopt;
}
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
    auto swapVariant = [](const std::variant<std::string, int64_t>& in) {
        return visit([](auto&& v) { return biosAttrCurrValue(v); }, in);
    };
    setBIOSTableAttrImpl(biosTableAttrs, attrName, swapVariant(attrValue),
                         attrType);
}

void HypNetworkMgr::setDefaultBIOSTableAttrsOnIntf(const std::string& intf)
{
    getDefaultBIOSTableAttrsOnIntf(
        intf, "ipv4", std::inserter(biosTableAttrs, std::end(biosTableAttrs)));
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
        auto mapperCall =
            bus.new_method_call(mapperBus, mapperObj, mapperIntf, "GetSubTree");

        mapperCall.append(biosMgrObj, depth, interfaces);

        auto mapperReply = bus.call(mapperCall);
        if (mapperReply.is_method_error())
        {
            lg2::error("Error in mapper call");
            elog<InternalFailure>();
        }

        ObjectTree objectTree;
        mapperReply.read(objectTree);

        auto fromFilteredList = [](auto& tree) {
            auto filterview =
                views::filter([&](auto& v) {
                    return std::string::npos != v.first.find(biosMgrIntf);
                }) |
                views::transform([](auto& v) { return v.first; }) |
                views::take(1);
            auto ret = tree | filterview;
            return !ret.empty() ? ret.front() : std::string();
        };

        auto objPath = objectTree.size() == 1 ? objectTree.begin()->first
                                              : fromFilteredList(objectTree);
        if (objPath.empty())
        {
            lg2::error(
                "No Object has implemented the interface {INTERFACE_NAME}",
                "INTERFACE_NAME", biosMgrIntf);
            elog<InternalFailure>();
        }

        std::variant<BiosBaseTableType> response;
        getDBusProp(objPath, biosMgrIntf, "BaseBIOSTable").read(response);

        std::visit(
            [&](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, BiosBaseTableType>)
                {
                    auto con = arg | views::filter([](auto item) {
                                   return item.first.rfind("vmi", 0) == 0;
                               }) |
                               views::transform(
                                   [](auto item) { return convert(item); }) |
                               views::filter(
                                   [](auto item) { return item.has_value(); }) |
                               views::transform(
                                   [](auto item) { return item.value(); });
                    biosTableAttrs = std::map<biosAttrName, biosAttrCurrValue>(
                        con.begin(), con.end());
                }
            },
            response);
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

    std::array<const char*, 2> names = {"eth0", "eth1"};
    auto ifaces = names | views::transform([&](auto e) {
                      return std::make_pair(
                          std::string(e),
                          std::make_unique<HypEthInterface>(
                              bus, (objectPath + "/" + e).c_str(), e, *this));
                  });
    interfaces = ethIntfMapType(ifaces.begin(), ifaces.end());
    // for (auto& p : interfaces)
    // {
    //     p.second->createIPAddressObjects();
    // }

    // // Call watch method to register for properties changed signal
    // // This method can be called only once
    // interfaces["eth0"]->watchBaseBiosTable();
}

void HypNetworkMgr::createSysConfObj()
{
    systemConf.reset(nullptr);
    this->systemConf =
        std::make_unique<HypSysConfig>(bus, objectPath + "/config", *this);
}

} // namespace network
} // namespace phosphor
