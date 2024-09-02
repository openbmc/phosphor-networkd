#pragma once

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{    
    class NcsiCommandCallback
    {
      public:
        virtual ~NcsiCommandCallback() = default;
        virtual void processResponse( const char* data ) = 0;

        static int callback( struct nl_msg* msg, void* arg );
    };
} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
