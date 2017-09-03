#include "rtnetlink_server.hpp"
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace phosphor
{
namespace network
{
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
                // Start the timer,when it expires
                // send the signal to the network manager to refresh
                // its interfaces.
                // TODO delete the below trace in later commit.
                std::cout << "Address Changed\n";

            } //end if

        } // end for

    } // end while

    return 0;
}

} // namespace rtnetlink
} // namespace network
} // namespace phosphor

int main(int argc, char* argv[])
{
    phosphor::network::rtnetlink::Server svr(
            phosphor::network::rtnetlink::eventHandler);
    return svr.run();
}
