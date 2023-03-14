/*
    created by le linh
    based on nrf, pcf, ausf
*/

#ifndef IDSF_EVENT_H
#define IDSF_EVENT_H

// #include "ogs-core.h"
#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

// typedef struct ogs_sbi_request_s ogs_sbi_request_t;
// typedef struct ogs_sbi_response_s ogs_sbi_response_t;
// typedef struct ogs_sbi_message_s ogs_sbi_message_t;
// typedef struct ogs_sbi_nf_instance_s ogs_sbi_nf_instance_t;
// typedef struct ogs_sbi_subscription_s ogs_sbi_subscription_t;

// typedef enum {
//     IDSF_EVT_BASE = OGS_FSM_USER_SIG,

//     IDSF_EVT_SBI_SERVER,
//     IDSF_EVT_SBI_CLIENT,
//     IDSF_EVT_SBI_TIMER,

//     IDSF_EVT_TOP,

// } idsf_event_e;

typedef struct idsf_event_s {
    ogs_event_t h;
    // int id;
    // int timer_id;

    // struct {
    //     ogs_sbi_request_t *request;
    //     ogs_sbi_response_t *response;
    //     void *data;

    //     ogs_sbi_message_t *message;
    // } sbi;

    // ogs_timer_t *timer;
} idsf_event_t;

// void idsf_event_init(void);
// void idsf_event_final(void);

// idsf_event_t *idsf_event_new(idsf_event_e id);
// void idsf_event_free(idsf_event_t *e);
idsf_event_t *idsf_event_new(int id);

const char *idsf_event_get_name(idsf_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* IDSF_EVENT_H */