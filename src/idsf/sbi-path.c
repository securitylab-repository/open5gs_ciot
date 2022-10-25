/* 
    created by le linh
    based on similar component of pcf,nrf,ausf
*/

#include "sbi-path.h"

static int server_cb(ogs_sbi_request_t *request, void *data)
{
    idsf_event_t *e = NULL;
    int rv;

    ogs_assert(request);
    ogs_assert(data);

    e = idsf_event_new(OGS_EVENT_SBI_SERVER);
    ogs_assert(e);

    e->h.sbi.request = request;
    e->h.sbi.data = data;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_warn("ogs_queue_push() failed:%d", (int)rv);
        ogs_sbi_request_free(request);
        ogs_event_free(e);
        return OGS_ERROR;
    }

    return OGS_OK;
}

static int client_cb(int status,ogs_sbi_response_t *response, void *data)
{
    idsf_event_t *e = NULL;
    int rv;

    if (status != OGS_OK) {
        ogs_log_message(
                status == OGS_DONE ? OGS_LOG_DEBUG : OGS_LOG_WARN, 0,
                "client_cb() failed [%d]", status);
        return OGS_ERROR;
    }

    ogs_assert(response);

    e = idsf_event_new(OGS_EVENT_SBI_CLIENT);
    ogs_assert(e);
    e->h.sbi.response = response;
    e->h.sbi.data = data;

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_warn("ogs_queue_push() failed:%d", (int)rv);
        ogs_sbi_response_free(response);
        ogs_event_free(e);
        return OGS_ERROR;
    }

    return OGS_OK;
}


int idsf_sbi_open(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_nf_service_t *service = NULL;

    // if (ogs_sbi_server_start_all(server_cb) != OGS_OK)
    //     return OGS_ERROR;

    /* Add SELF NF instance */
    nf_instance = ogs_sbi_self()->nf_instance;
    ogs_assert(nf_instance);
    ogs_sbi_nf_fsm_init(nf_instance);

    /* Build NF instance information. It will be transmitted to NRF. openAPI nf_type.h */
    ogs_sbi_nf_instance_build_default(nf_instance, OpenAPI_nf_type_IDSF);
    // for interact with other NF
    //ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_AMF);
    ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_SCP);
    ogs_sbi_nf_instance_add_allowed_nf_type(nf_instance, OpenAPI_nf_type_UPF);

     /* Build NF service information. It will be transmitted to NRF. */
    if (ogs_sbi_nf_service_is_available(
                OGS_SBI_SERVICE_NAME_NIDSF_DETECT)) {
        service = ogs_sbi_nf_service_build_default(
                    nf_instance,OGS_SBI_SERVICE_NAME_NIDSF_DETECT);
        ogs_assert(service);
        ogs_sbi_nf_service_add_version(
            service, OGS_SBI_API_V1,OGS_SBI_API_V1_0_0, NULL);
        // ogs_sbi_nf_service_add_allowed_nf_type(service, OpenAPI_nf_type_AMF);
    }

    /* Initialize NRF NF Instance */
    // ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance) {
        // if (NF_INSTANCE_IS_NRF(nf_instance)) {
    nf_instance = ogs_sbi_self()->nrf_instance;
    if (nf_instance) {
        ogs_sbi_client_t *client = NULL;

        /* Client callback is only used when NF sends to NRF */
        client = nf_instance->client;
        ogs_assert(client);
        client->cb = client_cb;

        /* NFRegister is sent and the response is received
            * by the above client callback. */
        ogs_sbi_nf_fsm_init(nf_instance);
    }
    
    /* Build Subscription-Data */
    //....

    if (ogs_sbi_server_start_all(server_cb) != OGS_OK)
        return OGS_ERROR;

    return OGS_OK;
}

void idsf_sbi_close(void)
{
    ogs_sbi_client_stop_all();
    ogs_sbi_server_stop_all();
}

// bool idsf_nnrf_nfm_send_nf_register(ogs_sbi_nf_instance_t *nf_instance)
// {
//     ogs_sbi_request_t *request = NULL;
//     ogs_sbi_client_t *client = NULL;

//     ogs_assert(nf_instance);
//     client = nf_instance->client;
//     ogs_assert(client);

//     request = idsf_nnrf_nfm_build_register();
//     ogs_expect_or_return_val(request, false);

//     ogs_info("IDSF N NRF request built");

//     return ogs_sbi_client_send_request(
//             client, client->cb, request, nf_instance);
// }

// bool idsf_sbi_send(ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_xact_t *xact)
// {
//     return ogs_sbi_send(nf_instance, client_cb, xact);
// }

bool idsf_sbi_send_request(ogs_sbi_nf_instance_t *nf_instance, void *data)
{
    ogs_assert(nf_instance);

    return ogs_sbi_send_request(nf_instance, client_cb, data);
}