#include "watch.hpp"

#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog-errors.hpp>

#include "xyz/openbmc_project/Common/error.hpp"

namespace phosphor
{
namespace network
{
namespace inotify
{

using namespace std::string_literals;
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;

Watch::~Watch()
{
    if ((fd() >= 0) && (wd >= 0))
    {
        inotify_rm_watch(fd(), wd);
    }
}

Watch::Watch(const phosphor::EventPtr& eventObj,
             const int flags,
             const uint32_t mask,
             const uint32_t events,
             const fs::path& path,
             UserType userFunc):
    flags(flags),
    mask(mask),
    events(events),
    path(path),
    fd(inotifyInit()),
    userFunc(userFunc)
{
    // Check if watch file exists.
    if (!fs::is_regular_file(path))
    {
        log<level::ERR>("Watch file doesn't exist",
                        entry("FILE=%s", path.c_str()));
        elog<InternalFailure>();
    }

    auto dirPath = path.parent_path();

    wd = inotify_add_watch(fd(), dirPath.c_str(), mask);
    if (-1 == wd)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during the inotify_add_watch call",
                        entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }

    auto rc = sd_event_add_io(eventObj.get(),
                              nullptr,
                              fd(),
                              events,
                              callback,
                              this);
    if (0 > rc)
    {
        // Failed to add to event loop
        log<level::ERR>("Error occurred during the sd_event_add_io call",
                        entry("RC=%d", rc));
        elog<InternalFailure>();
    }
}

int Watch::inotifyInit()
{
    auto fd = inotify_init1(flags);

    if (-1 == fd)
    {
        auto error = errno;
        log<level::ERR>("Error occurred during the inotify_init1",
                        entry("ERRNO=%d", error));
        elog<InternalFailure>();
    }

    return fd;
}

int Watch::callback(sd_event_source* s,
                    int fd,
                    uint32_t revents,
                    void* userdata)
{
    auto userData = static_cast<Watch*>(userdata);

    if (!(revents & userData->events))
    {
        return 0;
    }

    //Maximum inotify events supported in the buffer
    constexpr auto maxBytes = sizeof(struct inotify_event) + NAME_MAX + 1;
    uint8_t buffer[maxBytes];

    auto bytes = read(fd, buffer, maxBytes);
    if (0 > bytes)
    {
        //Failed to read inotify event
        //Report error and return
        auto error = errno;
        log<level::ERR>("Error occurred during the read",
                        entry("ERRNO=%d", error));
        report<InternalFailure>();
        return 0;
    }

    auto offset = 0;
    auto stateFile = userData->path.filename();
    while (offset < bytes)
    {
        auto event = reinterpret_cast<inotify_event*>(&buffer[offset]);
        auto mask = event->mask & userData->mask;

        if (mask)
        {
            if((event->len > 0) &&
               (strstr(event->name, stateFile.string().c_str())))
            {
                userData->userFunc(userData->path);
                break;
            }
        }

        offset += offsetof(inotify_event, name) + event->len;
    }

    return 0;
}

} // namespace inotify
} // namespace network
} // namespace phosphor

