/*
    created by le linh
    based on pcf, ausf
*/

#ifndef IDSF_TIMER_H
#define IDSF_TIMER_H

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* forward declaration */
typedef enum {
    IDSF_TIMER_BASE = 0,

    IDSF_TIMER_NF_INSTANCE_REGISTRATION_INTERVAL,
    IDSF_TIMER_NF_INSTANCE_HEARTBEAT_INTERVAL,
    IDSF_TIMER_NF_INSTANCE_NO_HEARTBEAT,
    IDSF_TIMER_NF_INSTANCE_VALIDITY,
    IDSF_TIMER_SUBSCRIPTION_VALIDITY,
    IDSF_TIMER_SBI_CLIENT_WAIT,

    MAX_NUM_OF_IDSF_TIMER,

} idsf_timer_e;

const char *idsf_timer_get_name(idsf_timer_e id);

void idsf_timer_nf_instance_registration_interval(void *data);
void idsf_timer_nf_instance_heartbeat_interval(void *data);
void idsf_timer_nf_instance_no_heartbeat(void *data);
void idsf_timer_nf_instance_validity(void *data);
void idsf_timer_subscription_validity(void *data);
void idsf_timer_sbi_client_wait_expire(void *data);

#ifdef __cplusplus
}
#endif

#endif /* IDSF_TIMER_H */