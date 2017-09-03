#include "config.h"
#include "rtnetlink_server.hpp"
#include "timer.hpp"

#include <chrono>
#include <functional>
#include <memory>

#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace phosphor
{
namespace network
{

std::unique_ptr<phosphor::network::Timer> timer = nullptr;

namespace rtnetlink
{


/* Call Back for the sd event loop */
static int eventHandler(sd_event_source* es, int fd, uint32_t revents,
                          void* userdata)
{
    char buffer[phosphor::network::rtnetlink::BUFSIZE] {};
    int len;

    auto nlh = reinterpret_cast<struct nlmsghdr*>(buffer);
    while ((len = recv(fd, nlh, phosphor::network::rtnetlink::BUFSIZE, 0)) > 0)
    {
        for (; (NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE);
             nlh = NLMSG_NEXT(nlh, len))
        {
            if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR)
            {
                // starting the timer here to make sure that we don't want
                // multiple dbus calls for an interface as interface may have
                // more then one IP.
                if (timer->isExpired())
                {
                    using namespace std::chrono;
                    auto time = duration_cast<microseconds>(
                            std::chrono::milliseconds(NETWORK_CHANGE_TIMEOUT));
                    // if start timer throws exception then let the application
                    // crash
                    timer->startTimer(time);
                }

            } //end if

        } // end for

    } // end while

    return 0;
}

} // namespace rtnetlink

void timerCallback()
{
    // Call the dbus method of network manager to refresh its interfaces.
    // will delete later in the next commit.
    std::cout << "Refresh network manager interfaces\n";

}

} // namespace network
} // namespace phosphor

int main(int argc, char* argv[])
{
    std::function<void()> func(std::bind(&phosphor::network::timerCallback));
    phosphor::network::timer = std::make_unique<phosphor::network::Timer>(func);

    phosphor::network::rtnetlink::Server svr(
                        phosphor::network::rtnetlink::eventHandler);
    return svr.run();
}
