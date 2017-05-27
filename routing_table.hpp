#pragma once

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <iostream>
#include <list>
#include <string>

namespace phosphor
{
namespace network
{
namespace route
{

struct Entry
{
    // destination network
    std::string destination;
    // gateway for this network.
    std::string gateway;
    // interface for this route
    std::string interface;
    Entry(std::string dest,
          std::string gtw,
          std::string intf) :
          destination(dest),
          gateway(gtw),
          interface(intf){}

    bool operator==(const Entry& rhs)
    {
        return this->destination == rhs.destination &&
               this->gateway == rhs.gateway &&
               this->interface == rhs.interface;
    }
};

using Map = std::map<std::string, struct Entry>;

class Table
{
    public:
        Table();
        ~Table() = default;
        Table(const Table&) = delete;
        Table& operator=(const Table&) = delete;
        Table(Table&&) = default;
        Table& operator=(Table &&) = default;

    private:

        /**
         * @brief read the routing data from the socket and fill the buffer.
         *
         * @param[in] bufPtr - unique pointer to confidentiality algorithm
         *                     instance
         */
        int readNetLinkSock(int sockFd, char* bufPtr);
        /**
         * @brief Parse the route and add it to the route list.
         *
         * @param[in] nlHdr - net link message header.
         */
        void parseRoutes(struct nlmsghdr* nlHdr);

        std::string defaultGateway; // default gateway
        Map routeList; //List of routes

    public:

        /**
         * @brief gets the list of routes.
         *
         * @returns list of routes.
         */
        Map getRoutes();

        /**
         * @brief gets the default gateway.
         *
         * @returns the default gateway.
         */
        std::string getDefaultGateway() const
        {
            return defaultGateway;
        };

        /**
         * @brief get the gateway for the network.
         * @param[in] addressFamily - ip address family(AF_INET/AF_INET6)
         * @param[in] ipaddress - ip address.
         * @param[in] prefix - prefix length.
         * @returns the gatway for the given network.
         */
        std::string getGateway(int addressFamily,
                               const std::string& ipaddress,
                               uint8_t prefix) const;

};

}// namespace route
}// namespace network
}// namespace phosphor
