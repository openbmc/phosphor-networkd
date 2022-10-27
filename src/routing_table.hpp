#pragma once
#include "types.hpp"

#include <unordered_map>

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
        return gws4;
    }

    /**
     * @brief gets the default v6 gateway.
     *
     * @returns the default v6 gateway list.
     */
    inline const auto& getDefaultGateway6() const
    {
        return gws6;
    };

  private:
    std::unordered_map<unsigned, in_addr> gws4;
    std::unordered_map<unsigned, in6_addr> gws6;
};

} // namespace route
} // namespace network
} // namespace phosphor
