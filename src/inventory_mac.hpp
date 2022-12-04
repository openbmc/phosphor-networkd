#pragma once
#include <memory>
#include <sdbusplus/bus.hpp>

namespace phosphor::network
{

class Manager;

namespace inventory
{

struct Runtime
{
    virtual ~Runtime() = default;
};
std::unique_ptr<Runtime> watch(sdbusplus::bus_t& bus, Manager& m);

} // namespace inventory
} // namespace phosphor::network
