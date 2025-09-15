#pragma once

#include "lldp_interface.hpp"

#include <sdbusplus/bus.hpp>
#include <sdeventplus/event.hpp>

#include <map>
#include <unordered_map>
#include <vector>
#include <string>

namespace phosphor
{
namespace network
{
namespace lldp
{
class Interface;
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

    std::unordered_map<std::string, std::unique_ptr<Interface>> ifaces;
};

} // namespace lldp
} // namespace network
} // namespace phosphor
