#pragma once
#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>

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

  private:
    sdbusplus::bus_t& bus;
    sdeventplus::Event& event;
    std::string objPath;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
