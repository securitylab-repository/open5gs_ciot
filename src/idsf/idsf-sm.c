/*
    created by le linh
    based on pcf, ausf
*/

#include "sbi-path.h"
#include "nnrf-handler.h"

void idsf_state_initial(ogs_fsm_t *s, idsf_event_t *e)
{
    idsf_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &idsf_state_operational);
}

void idsf_state_final(ogs_fsm_t *s, idsf_event_t *e)
{
    idsf_sm_debug(e);
}

void idsf_state_operational(ogs_fsm_t *s, idsf_event_t *e)
{
    int rv;

    ogs_sbi_stream_t *stream = NULL;
    ogs_sbi_request_t *request = NULL;

    ogs_sbi_nf_instance_t *nf_instance = NULL;
    ogs_sbi_subscription_t *subscription = NULL;
    ogs_sbi_response_t *response = NULL;
    ogs_sbi_message_t message;

    ogs_sbi_xact_t *sbi_xact = NULL;

    idsf_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        break;

    case OGS_FSM_EXIT_SIG:
        break;

    //need declare functionality for IDS to have SBI
    case IDSF_EVT_SBI_SERVER:
        request = e->sbi.request;
        ogs_assert(request);
        stream = e->sbi.data;
        ogs_assert(stream);
        
        rv = ogs_sbi_parse_request(&message, request);
        if (rv != OGS_OK) {
            /* 'message' buffer is released in ogs_sbi_parse_request() */
            ogs_error("cannot parse HTTP message");
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    NULL, "cannot parse HTTP message", NULL));
            break;
        }

        if (strcmp(message.h.api.version, OGS_SBI_API_V1) != 0) {
            ogs_error("Not supported version [%s]", message.h.api.version);
            ogs_assert(true ==
                ogs_sbi_server_send_error(
                    stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    &message, "Not supported version", NULL));
            ogs_sbi_message_free(&message);
            break;
        }

        ogs_sbi_message_free(&message);

        break;
    
    case IDSF_EVT_SBI_CLIENT:
        ogs_assert(e);

        response = e->sbi.response;
        ogs_assert(response);

        rv = ogs_sbi_parse_response(&message, response);
        if (rv != OGS_OK) {
            ogs_error("cannot parse HTTP response");
            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;
        }

        if (strcmp(message.h.api.version, OGS_SBI_API_V1) != 0) {
            ogs_error("Not supported version [%s]", message.h.api.version);
            ogs_sbi_message_free(&message);
            ogs_sbi_response_free(response);
            break;
        }

        ogs_sbi_message_free(&message);
        ogs_sbi_response_free(response);

        break;
    
    case IDSF_EVT_SBI_TIMER:
        ogs_assert(e);
        
        switch(e->timer_id) {
        case IDSF_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
        case IDSF_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
        case IDSF_TIMER_NF_INSTANCE_NO_HEARTBEAT:
        case IDSF_TIMER_NF_INSTANCE_VALIDITY:
            nf_instance = e->sbi.data;
            ogs_assert(nf_instance);
            ogs_assert(OGS_FSM_STATE(&nf_instance->sm));

            ogs_fsm_dispatch(&nf_instance->sm, e);
            if (OGS_FSM_CHECK(&nf_instance->sm, idsf_nf_state_exception))
                ogs_error("[%s:%s] State machine exception [%d]",
                        OpenAPI_nf_type_ToString(nf_instance->nf_type),
                        nf_instance->id, e->timer_id);
            break;

        case IDSF_TIMER_SUBSCRIPTION_VALIDITY:
            subscription = e->sbi.data;
            ogs_assert(subscription);

            ogs_assert(ogs_sbi_self()->nf_instance);
            ogs_assert(true ==
                ogs_nnrf_nfm_send_nf_status_subscribe(subscription->client,
                    ogs_sbi_self()->nf_instance->nf_type,
                    subscription->req_nf_instance_id,
                    subscription->subscr_cond.nf_type));

            ogs_info("[%s] Subscription validity expired", subscription->id);
            ogs_sbi_subscription_remove(subscription);
            break;

        case IDSF_TIMER_SBI_CLIENT_WAIT:
            sbi_xact = e->sbi.data;
            ogs_assert(sbi_xact);

            stream = sbi_xact->assoc_stream;
            ogs_assert(stream);

            ogs_sbi_xact_remove(sbi_xact);

            ogs_error("Cannot receive SBI message");
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_GATEWAY_TIMEOUT, NULL,
                    "Cannot receive SBI message", NULL));
            break;
        default:
            ogs_error("Unknown timer[%s:%d]",
                    idsf_timer_get_name(e->timer_id), e->timer_id);
        }
        break;

    default:
        ogs_error("No handler for event %s", idsf_event_get_name(e));
        break;
    }
}

