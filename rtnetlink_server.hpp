#pragma once

#include <iostream>
#include <string>
#include <sys/types.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>

namespace phosphor
{
namespace network
{
namespace rtnetlink
{

constexpr auto BUFSIZE = 4096;

/** General rtnetlink server which waits for the POLLIN event
    and calls the  call back once it gets the event.
    usage would be create the server with the  call back
    and call the run method.
 */

class Server
{

    public:

        Server(sd_event_io_handler_t cb):
            callme(cb) {};

        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;
        Server(Server&&) = default;
        Server& operator=(Server &&) = default;

        sd_event_io_handler_t callme;

        int run();

};

} //namespace rtnetlink
} //namespce network
} //namespace phosphor
