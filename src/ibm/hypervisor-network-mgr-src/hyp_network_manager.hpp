#pragma once

#include "hyp_ethernet_interface.hpp"
#include "hyp_sys_config.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <stdplus/str/maps.hpp>

namespace phosphor
{
namespace network
{

class HypEthInterface;
class HypSysConfig;

using biosAttrName = std::string;
using biosAttrType = std::string;
using biosAttrIsReadOnly = bool;
using biosAttrDispName = std::string;
using biosAttrHelpText = std::string;
using biosAttrMenuPath = std::string;
using biosAttrCurrValue = std::variant<int64_t, std::string>;
using biosAttrDefaultValue = std::variant<int64_t, std::string>;
using biosAttrOptions =
    std::tuple<std::string, std::variant<int64_t, std::string>>;

using biosTableType = std::map<biosAttrName, biosAttrCurrValue>;
using BiosBaseTableItemType =
    std::pair<biosAttrName,
              std::tuple<biosAttrType, biosAttrIsReadOnly, biosAttrDispName,
                         biosAttrHelpText, biosAttrMenuPath, biosAttrCurrValue,
                         biosAttrDefaultValue, std::vector<biosAttrOptions>>>;
using BiosBaseTableType = std::vector<BiosBaseTableItemType>;

enum BiosBaseTableIndex
{
    biosBaseAttrType = 0,
    biosBaseReadonlyStatus,
    biosBaseDisplayName,
    biosBaseDescription,
    biosBaseMenuPath,
    biosBaseCurrValue,
    biosBaseDefaultValue,
    biosBaseOptions
};

using SystemConfPtr = std::unique_ptr<HypSysConfig>;
using ethIntfMapType = stdplus::string_umap<std::unique_ptr<HypEthInterface>>;

/** @class Manager
 *  @brief Implementation for the
 *         xyz.openbmc_project.Network.Hypervisor DBus API.
 */
class HypNetworkMgr
{
  public:
    HypNetworkMgr() = delete;
    HypNetworkMgr(const HypNetworkMgr&) = delete;
    HypNetworkMgr& operator=(const HypNetworkMgr&) = delete;
    HypNetworkMgr(HypNetworkMgr&&) = delete;
    HypNetworkMgr& operator=(HypNetworkMgr&&) = delete;
    virtual ~HypNetworkMgr() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */

    HypNetworkMgr(sdbusplus::bus_t& bus, const char* path) :
        bus(bus), objectPath(path){};
    /** @brief Get the BaseBiosTable attributes
     *
     * @return attributes list
     */
    inline biosTableType getBIOSTableAttrs()
    {
        return biosTableAttrs;
    }

    /** @brief Set specific attribute and its value to
     *         the biosTableAttrs data member
     *
     * @param[in] attrName  - attribute name in biosTableAttrs
     * @param[in] attrValue - attribute value
     * @param[in] attrType  - attribute type
     *
     */
    void setBIOSTableAttr(std::string attrName,
                          std::variant<std::string, int64_t> attrValue,
                          std::string attrType);

    /** @brief Get the ethernet interfaces list data member
     *
     * @return ethernet interfaces list
     */
    inline const auto& getEthIntfList()
    {
        return interfaces;
    }

    /** @brief Method to set all the interface 0 attributes
     *         to its default value in biosTableAttrs data member
     */
    void setDefaultBIOSTableAttrsOnIntf(const std::string& intf);

    /** @brief Method to set the hostname attribute
     *         to its default value in biosTableAttrs
     *         data member
     */
    void setDefaultHostnameInBIOSTableAttrs();

    /** @brief Fetch the interface and the ipaddress details
     *         from the Bios table and create the hyp ethernet interfaces
     *         dbus object.
     */
    void createIfObjects();

    /** @brief Creates system config object
     */
    void createSysConfObj();

    /** @brief gets the system conf object.
     *
     */
    const SystemConfPtr& getSystemConf()
    {
        return systemConf;
    }

  protected:
    /**
     * @brief get Dbus Prop
     *
     * @param[in] objectName - dbus Object
     * @param[in] interface - dbus Interface
     * @param[in] kw - keyword under the interface
     *
     * @return dbus call response
     */
    auto getDBusProp(const std::string& objectName,
                     const std::string& interface, const std::string& kw);

    /** @brief Setter method for biosTableAttrs data member
     *         GET operation on the BIOS table to
     *         read all the hyp attributes (name, value pair)
     *         and push them to biosTableAttrs data member
     */
    void setBIOSTableAttrs();

    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief pointer to system conf object. */
    SystemConfPtr systemConf = nullptr;

    /** @brief Persistent map of EthernetInterface dbus
     *         objects and their names
     */
    ethIntfMapType interfaces;

    /** @brief map of bios table attrs and values */
    std::map<biosAttrName, biosAttrCurrValue> biosTableAttrs;
};

} // namespace network
} // namespace phosphor
