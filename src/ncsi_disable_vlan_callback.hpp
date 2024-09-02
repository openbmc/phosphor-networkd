#pragma once

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
        virtual void processResponse( const uint8_t* data, size_t len )override;
    };
} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
