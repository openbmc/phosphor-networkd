#include <iostream>

namespace phosphor
{
namespace network
{
namespace ncsi
{

namespace command
{
    static constexpr uint8_t UNSPEC = 0;
    static constexpr uint8_t PKG_INFO = 1;
    static constexpr uint8_t SET_INTERFACE = 2;
    static constexpr uint8_t CLEAR_INTERFACE = 3;
}// namespace command

namespace attribute
{
    static constexpr uint8_t UNSPEC = 0;
    static constexpr uint8_t IFINDEX = 1;
    static constexpr uint8_t PACKAGE_LIST = 2;
    static constexpr uint8_t PACKAGE_ID = 3;
    static constexpr uint8_t CHANNEL_ID = 4;
    static constexpr uint8_t MAX = 5;
}// namespace attribute

namespace package
{
    static constexpr uint8_t UNSPEC = 0;
    static constexpr uint8_t ATTR = 1;
    static constexpr uint8_t ATTR_ID = 2;
    static constexpr uint8_t ATTR_FORCED = 3;
    static constexpr uint8_t ATTR_CHANNEL_LIST = 4;
    static constexpr uint8_t ATTR_MAX = 5;
}// namespace package
namespace channel
{
    static constexpr uint8_t UNSPEC = 0;
    static constexpr uint8_t ATTR = 1;
    static constexpr uint8_t ATTR_ID = 2;
    static constexpr uint8_t ATTR_VERSION_MAJOR = 3;
    static constexpr uint8_t ATTR_VERSION_MINOR = 4;
    static constexpr uint8_t ATTR_VERSION_STR = 5;
    static constexpr uint8_t ATTR_LINK_STATE = 6;
    static constexpr uint8_t ATTR_ACTIVE = 7;
    static constexpr uint8_t ATTR_FORCED = 8;
    static constexpr uint8_t ATTR_VLAN_LIST = 9;
    static constexpr uint8_t ATTR_VLAN_ID = 10;
    static constexpr uint8_t ATTR_MAX = 11;

}// namespace channel

namespace vlan
{
    static constexpr uint8_t UNSPEC = 0;
    static constexpr uint8_t INFO = 1;
    static constexpr uint8_t INFO_ID = 2;
    static constexpr uint8_t INFO_PROTO = 3;
    static constexpr uint8_t INFO_MAX = 4;
}// namespace vlan

/* @brief  This function will ask underlying NCSI driver
 *         to set a specific  package or package/channel
 *         combination as the preferred choice.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @param[in] channel - Channel number with in the package.
 * @returns 0 on success and negative value for failure.
 */
int setChannel( int ifindex, int package, int channel);

/* @brief  This function will ask underlying NCSI driver
 *         to clear any preferred setting from the given
 *         interface.
 *         This function talks with the NCSI driver over
 *         netlink messages.
 * @param[in] ifindex - Interface Index.
 * @returns 0 on success and negative value for failure.
 */
int clearInterface(int ifindex);

/* @brief  This function is used to dump all the info
 *         of the package and the channels underlying
 *         the package.
 * @param[in] ifindex - Interface Index.
 * @param[in] package - NCSI Package.
 * @returns 0 on success and negative value for failure.
 */
int getInfo(int ifindex, int package);

}//namespace ncsi
}//namespace network
}//namespace phosphor

