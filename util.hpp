#pragma once

#include <unistd.h>

namespace phosphor
{
namespace network
{

/** @brief converts the given subnet into prefix notation **/
uint8_t toCidr(int addressFamily,  const std::string& mask);

/** @brief converts the prefix into subnetmask **/
std::string toMask(int addressFamily, uint8_t prefix);

/* @brief checks that the given ip address is link local or not.
 *  @returns true if it is linklocal otherwise false
 */
bool isLinkLocal(const std::string& address);

/* @brief checks that the given ip address is link local or not.
 *  @returns true if it is linklocal otherwise false
 */
std::string getNetwork(int addressFamily, const std::string& ipaddress,
                       uint8_t prefix);

} //namespace network

class Descriptor
{
    private:
        /** default value */
        int fd = -1;

    public:
        Descriptor() = delete;
        Descriptor(const Descriptor&) = delete;
        Descriptor& operator=(const Descriptor&) = delete;
        Descriptor(Descriptor&&) = delete;
        Descriptor& operator=(Descriptor &&) = delete;

        Descriptor(int fd) : fd(fd) {}

        ~Descriptor()
        {
            if (fd >= 0)
            {
                close(fd);
            }
        }

        int operator()() const
        {
            return fd;
        }
};
} //namespace phosphor
