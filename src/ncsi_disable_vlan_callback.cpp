#include "ncsi_disable_vlan_callback.hpp"

namespace phosphor
{
namespace network
{
namespace ncsi
{
namespace internal
{ 
    void DisableVlanCallback::processResponse( const uint8_t* data,
                                               size_t len )override
    {
        DisableVlanResponse* response =
        std::bit_cast<DisableVlanResponse*>(data);

        lg2::debug("NCSI Response packet type : {RESPONSE_PKT_TYPE}",
        "RESPONSE_PKT_TYPE", lg2::hex, response->header.type);

        auto respHdrLen = htons(response->header.length);

        lg2::debug("NCSI Response length : {RESPONSE_LEN}", "RESPONSE_LEN",
        lg2::hex, respHdrLen);

        response->responseCode = ntohs(response->responseCode);
        response->reasonCode = ntohs(response->reasonCode);

        lg2::debug("NCSI Response Code : {RESPONSE_CODE}", "RESPONSE_CODE",
        lg2::hex, response->responseCode);
        lg2::debug("NCSI Reason Code : {REASON_CODE}", "REASON_CODE", lg2::hex,
        response->reasonCode);  
    }
}
}
}
