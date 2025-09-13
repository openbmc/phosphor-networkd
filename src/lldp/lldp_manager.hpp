#pragma once
#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>
#include <stdplus/pinned.hpp>

namespace phosphor
{
namespace network
{
namespace lldp
{

class Manager
{
  public:
    Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event,
            const std::string& objPath);

  protected:
    sdbusplus::bus_t& bus;
    sdeventplus::Event& event;
    std::string objPath;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
