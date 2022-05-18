#pragma once
#include <linux/netlink.h>

#include <map>
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
     * @brief Parse the route and add it to the route list.
     *
     * @param[in] nlHdr - net link message header.
     */
    void parseRoutes(const struct nlmsghdr& nlHdr, std::string_view msg);

    std::map<std::string, std::string> defaultGateway;  // default gateway list
    std::map<std::string, std::string> defaultGateway6; // default gateway list
};

} // namespace route
} // namespace network
} // namespace phosphor
