#pragma once

#include "ncsi_util.hpp"
#include "ncsi_cmd_callback.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{    
    struct DisableVlanResponse
    {
        NCSIPacketHeader header;
        uint16_t responseCode;
        uint16_t reasonCode;
        uint32_t checksum;
        uint8_t  reserved[22];
    };

    class DisableVlanCallback : public NcsiCommandCallback
    {
      public:
        virtual void processResponse(const char* data)override;
    };
} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
