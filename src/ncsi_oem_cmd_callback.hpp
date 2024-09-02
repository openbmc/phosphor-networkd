#pragma once

#include "ncsi_cmd_callback.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{    
    class SendOemCommandCallback : public NcsiCommandCallback
    {
      public:
        virtual void processResponse([[maybe_unused]] const char* data) 
        {
        }
    };
} // namespace internal
} // namespace ncsi
} // namespace network
} // namespace phosphor
