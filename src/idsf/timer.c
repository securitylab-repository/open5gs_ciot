/*
    created by le linh
    based on pcf, ausf
*/

#include "context.h"

const char *idsf_timer_get_name(idsf_timer_e id)
{
    switch (id) {
    case IDSF_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
        return "IDSF_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL";
    case IDSF_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
        return "IDSF_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL";
    case IDSF_TIMER_NF_INSTANCE_NO_HEARTBEAT:
        return "IDSF_TIMER_NF_INSTANCE_NO_HEARTBEAT";
    case IDSF_TIMER_NF_INSTANCE_VALIDITY:
        return "IDSF_TIMER_NF_INSTANCE_VALIDITY";
    case IDSF_TIMER_SUBSCRIPTION_VALIDITY:
        return "IDSF_TIMER_SUBSCRIPTION_VALIDITY";
    case IDSF_TIMER_SBI_CLIENT_WAIT:
        return "IDSF_TIMER_SBI_CLIENT_WAIT";
    default: 
       break;
    }

    return "UNKNOWN_TIMER";
}

static void sbi_timer_send_event(int timer_id, void *data)
{
    int rv;
    idsf_event_t *e = NULL;
    ogs_assert(data);

    switch (timer_id) {
    case IDSF_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL:
    case IDSF_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL:
    case IDSF_TIMER_NF_INSTANCE_NO_HEARTBEAT:
    case IDSF_TIMER_NF_INSTANCE_VALIDITY:
    case IDSF_TIMER_SUBSCRIPTION_VALIDITY:
        e = idsf_event_new(IDSF_EVT_SBI_TIMER);
        ogs_assert(e);
        e->timer_id = timer_id;
        e->sbi.data = data;
        break;
    case IDSF_TIMER_SBI_CLIENT_WAIT:
        e = idsf_event_new(IDSF_EVT_SBI_TIMER);
        if (!e) {
            ogs_sbi_xact_t *sbi_xact = data;
            ogs_assert(sbi_xact);

            ogs_error("sbi_timer_send_event() failed");
            ogs_sbi_xact_remove(sbi_xact);
            return;
        }
        e->timer_id = timer_id;
        e->sbi.data = data;
        break;
    default:
        ogs_fatal("Unknown timer id[%d]", timer_id);
        ogs_assert_if_reached();
        break;
    }

    rv = ogs_queue_push(ogs_app()->queue, e);
    if (rv != OGS_OK) {
        ogs_warn("ogs_queue_push() failed [%d] in %s",
                (int)rv, idsf_timer_get_name(e->timer_id));
        idsf_event_free(e);
    }
}

void idsf_timer_nf_instance_registration_interval(void *data)
{
    sbi_timer_send_event(IDSF_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL, data);
}

void idsf_timer_nf_instance_heartbeat_interval(void *data)
{
    sbi_timer_send_event(IDSF_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL, data);
}

void idsf_timer_nf_instance_no_heartbeat(void *data)
{
    sbi_timer_send_event(IDSF_TIMER_NF_INSTANCE_NO_HEARTBEAT, data);
}

void idsf_timer_nf_instance_validity(void *data)
{
    sbi_timer_send_event(IDSF_TIMER_NF_INSTANCE_VALIDITY, data);
}

void idsf_timer_subscription_validity(void *data)
{
    sbi_timer_send_event(IDSF_TIMER_SUBSCRIPTION_VALIDITY, data);
}

void idsf_timer_sbi_client_wait_expire(void *data)
{
    sbi_timer_send_event(IDSF_TIMER_SBI_CLIENT_WAIT, data);
}