#pragma once
#include <linux/netlink.h>

#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace phosphor
{
namespace network
{
namespace route
{
class Table
{
  public:
    /** @brief Rebuilds the routing table from the kernel */
    void refresh();

    /**
     * @brief gets the default v4 gateway.
     *
     * @returns the default v4 gateway list.
     */
    inline const auto& getDefaultGateway() const
    {
        return defaultGateway;
    }

    /**
     * @brief gets the default v6 gateway.
     *
     * @returns the default v6 gateway list.
     */
    inline const auto& getDefaultGateway6() const
    {
        return defaultGateway6;
    };

  private:
    /**
     * @brief Handle the response of RTM_GETLINK netlink message.
     *
     * @param[in] hdr - netlink message header.
     */
    void handleRtmGetRoute(const nlmsghdr& hdr, std::string_view msg);

    /**
     * @brief Parse routing attributes in a message.
     *
     * @param[in] family - address family.
     * @param[in] ifindex - (optional) interface index, used for handling nested
     *                      RTAs in RTA_MULTIPATH.
     */
    void parseRtAttrs(std::string_view msg, int family,
                      std::optional<int> ifindex = std::nullopt);

    /**
     * @brief Parse the content of RTA_MULTIPATH routing attribute.
     *
     * @param[in] family - address family.
     */
    void parseRtaMultipath(std::string_view msg, int family);

    /**
     * @brief Update the default gateway list.
     *
     * @param[in] family - address family.
     * @param[in] ifname - interface name.
     * @param[in] gateway - gateway address string.
     */
    void updateGateway(int family, const std::string& ifname,
                       const std::string& gateway);

    std::map<std::string, std::string> defaultGateway;  // default gateway list
    std::map<std::string, std::string> defaultGateway6; // default gateway list
};

} // namespace route
} // namespace network
} // namespace phosphor
