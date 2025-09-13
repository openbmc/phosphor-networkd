#pragma once
#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>

namespace phosphor
{
namespace network
{
namespace lldp
{

class LLDPManager
{
  public:
    LLDPManager(sdbusplus::bus_t& bus, sdeventplus::Event& event);

    static constexpr std::string_view objPath =
        "/xyz/openbmc_project/network/lldp";

  protected:
    sdbusplus::bus_t& bus;
    sdeventplus::Event& event;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
