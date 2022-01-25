#include "watch.hpp"

#include <errno.h>
#include <sys/inotify.h>
#include <systemd/sd-event.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include <utility>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace network
{
namespace inotify
{

using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Watch::Watch(phosphor::network::EventPtr& eventPtr, std::filesystem::path path,
             uint32_t mask, UserCallBack userFunc) :
    userFunc(std::move(userFunc))
{
    int r = sd_event_add_inotify(eventPtr.get(), &source, path.c_str(), mask,
                                 processEvent, this);
    if (r < 0)
    {
        // Failed to add to event loop
        log<level::ERR>("Error registering with sd_event_add_inotify",
                        entry("ERRNO=%d", -r));
        elog<InternalFailure>();
    }
}

Watch::~Watch()
{
    sd_event_source_unref(source);
}

int Watch::processEvent(sd_event_source*, const struct inotify_event* event,
                        void* userdata)
{
    static_cast<Watch*>(userdata)->userFunc(event->name);
    return 0;
}

} // namespace inotify
} // namespace network
} // namespace phosphor
