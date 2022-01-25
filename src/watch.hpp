#pragma once
#include "types.hpp"

#include <functional>
#include <filesystem>

namespace phosphor
{
namespace network
{
namespace inotify
{

// Auxiliary callback to be invoked on inotify events
using UserCallBack = std::function<void(const char *)>;

/** @class Watch
 *
 *  @brief Adds inotify watch on directory
 *
 *  @details Calls back user function on matching events
 */
class Watch
{
  public:
    Watch() = delete;
    Watch(const Watch&) = delete;
    Watch& operator=(const Watch&) = delete;
    Watch(Watch&&) = delete;
    Watch& operator=(Watch&&) = delete;

    /** @brief Hooks inotify watch with sd-event
     *
     *  @param[in] eventPtr - Reference to sd_event wrapped in unique_ptr
     *  @param[in] path     - File path to be watched
     *  @param[in] mask     - Mask of events to be supplied to inotify
     *  @param[in] userFunc - User specific callback function on events
     */
    Watch(phosphor::network::EventPtr& eventPtr, const std::filesystem::path path,
          uint32_t mask,
          UserCallBack userFunc);

    ~Watch();

  private:
    /** @brief User callback function */
    UserCallBack userFunc;

    /** @brief Event source */
    sd_event_source *source = nullptr;

    static int processEvent(sd_event_source* source, const struct inotify_event *event, 
                         void* userdata);
};

} // namespace inotify
} // namespace network
} // namespace phosphor
