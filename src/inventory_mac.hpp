#pragma once
#include <memory>
#include <stdplus/pinned.hpp>

namespace sdbusplus::bus
{
class bus;
}

namespace phosphor::network
{

class Manager;

namespace inventory
{

struct Runtime
{
    virtual ~Runtime() = default;
};
std::unique_ptr<Runtime> watch(stdplus::PinnedRef<sdbusplus::bus::bus> bus,
                               stdplus::PinnedRef<Manager> m);

} // namespace inventory
} // namespace phosphor::network
