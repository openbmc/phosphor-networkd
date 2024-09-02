#pragma once

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{    
    class OemCallback : public NcsiCommandCallback
    {
      public:
        virtual void processResponse( const uint8_t* data, size_t len ) override
        {
        }
    };
} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
