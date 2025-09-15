#pragma once

#include "lldp_neighbor.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>
#include <stdplus/pinned.hpp>

#include <map>

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

    std::vector<std::string> getInterfaces();

  protected:
    sdbusplus::bus_t& bus;
    sdeventplus::Event& event;
    std::string objPath;
    std::unordered_map<std::string, std::unique_ptr<Neighbor>> neighbors;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
