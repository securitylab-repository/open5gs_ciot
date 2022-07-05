/* 
    created by le linh
    based on similar component of pcf,ausf
*/

#include "nnrf-build.h"

ogs_sbi_request_t *idsf_nnrf_nfm_build_register(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;

    OpenAPI_nf_profile_t *NFProfile = NULL;

    nf_instance = ogs_sbi_self()->nf_instance;
    ogs_assert(nf_instance);
    ogs_assert(nf_instance->id);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_PUT;
    message.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NNRF_NFM;
    message.h.api.version = (char *)OGS_SBI_API_V1;
    message.h.resource.component[0] =
        (char *)OGS_SBI_RESOURCE_NAME_NF_INSTANCES;
    message.h.resource.component[1] = nf_instance->id;

    message.http.content_encoding = (char*)ogs_sbi_self()->content_encoding;

    NFProfile = ogs_nnrf_nfm_build_nf_profile();
    ogs_expect_or_return_val(NFProfile, NULL);

    message.NFProfile = NFProfile;

    request = ogs_sbi_build_request(&message);

    ogs_sbi_nnrf_free_nf_profile(NFProfile);

    return request;
}