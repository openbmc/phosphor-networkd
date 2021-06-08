#pragma once

#include "hyp_ethernet_interface.hpp"
#include "types.hpp"
#include "util.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/source/event.hpp>

namespace phosphor
{
namespace network
{

class HypEthInterface;

using biosTableType = std::map<std::string, std::variant<int64_t, std::string>>;

using BiosBaseTableType = std::vector<std::pair<
    std::string,
    std::tuple<
        std::string, bool, std::string, std::string, std::string,
        std::variant<int64_t, std::string>, std::variant<int64_t, std::string>,
        std::vector<
            std::tuple<std::string, std::variant<int64_t, std::string>>>>>>;

using BiosBaseTableItemType = std::pair<
    std::string,
    std::tuple<
        std::string, bool, std::string, std::string, std::string,
        std::variant<int64_t, std::string>, std::variant<int64_t, std::string>,
        std::vector<
            std::tuple<std::string, std::variant<int64_t, std::string>>>>>;

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
     *  @param[in] event - event.
     *  @param[in] path - Path to attach at.
     */
    HypNetworkMgr(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                  const char* path) :
        bus(bus),
        event(event), objectPath(path)
    {
        // Create the hypervisor eth interface objects
        createIfObjects();
    };

    /**
     * @brief make Dbus Call
     *
     * @param[in] objectName - dbus Object
     * @param[in] interface - dbus Interface
     * @param[in] kw - keyword under the interface
     *
     * @return dbus call response
     */
    auto makeDBusCall(const std::string& objectName,
                      const std::string& interface, const std::string& kw);

    /** @brief Fetch the interface and the ipaddress details
     *         from the Bios table and create the hyp ethernet interfaces
     *         dbus object.
     */
    void createIfObjects();

    /** @brief Get the hypervisor eth interfaces count
     *
     * @return number of interfaces
     */
    uint16_t getIntfCount();

    /** @brief Get the BaseBiosTable attributes
     *
     * @return attributes list
     */
    biosTableType getBIOSTableAttrs();

    /** @brief GET operation on the BIOS table to
     *        read the hyp attrbutes and SET them
     *        to biosTableAttrs data member
     */
    void setBIOSTableAttrs();

    /** @brief Set specific attribute and its value to
     *         the biosTableAttrs data member
     *
     * @param[in] attrName  - attribute name in biosTableAttrs
     * @param[in] attrValue - attribute value
     * @param[in] attrType  - attribute type
     *
     */
    void setBIOSTableAttrs(std::string attrName,
                           std::variant<std::string, int64_t> attrValue,
                           std::string attrType);

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;

    /**  sdevent Event handle. */
    sdeventplus::Event& event;

    /** @brief object path */
    std::string objectPath;

    /** @brief Persistent map of EthernetInterface dbus
     *         objects and their names
     */
    std::map<std::string, std::shared_ptr<HypEthInterface>> interfaces;

    /** @brief interface count */
    uint16_t intfCount;

    /** @brief map of bios table attrs and values */
    std::map<std::string, std::variant<int64_t, std::string>> biosTableAttrs;
};

} // namespace network
} // namespace phosphor
