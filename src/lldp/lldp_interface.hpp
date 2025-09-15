#pragma once

#include <sdbusplus/server/object.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace phosphor
{
namespace network
{
namespace lldp
{

class Manager;

class Interface
{
  public:
    Interface() = delete;
    Interface(const Interface&) = delete;
    Interface& operator=(const Interface&) = delete;

    Interface(sdbusplus::bus_t& bus, Manager& manager,
              const std::string& objPath, const std::string& ifname);

    ~Interface() = default;

  private:
    Manager& manager;
    sdbusplus::bus_t& busRef;
    std::string objPath;
    std::string ifname;
};
} // namespace lldp
} // namespace network
} // namespace phosphor
