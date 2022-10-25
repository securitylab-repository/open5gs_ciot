/*
    created by le linh
    based on pcf, ausf, scp
*/

#ifndef IDSF_SM_H
#define IDSF_SM_H

// need create
#include "event.h"

#ifdef __cplusplus
extern "C" {
#endif

void idsf_state_initial(ogs_fsm_t *s, idsf_event_t *e);
void idsf_state_final(ogs_fsm_t *s, idsf_event_t *e);
void idsf_state_operational(ogs_fsm_t *s, idsf_event_t *e);
void idsf_state_exception(ogs_fsm_t *s, idsf_event_t *e);

// void idsf_nf_fsm_init(ogs_sbi_nf_instance_t *nf_instance);
// void idsf_nf_fsm_fini(ogs_sbi_nf_instance_t *nf_instance);

// void idsf_nf_state_initial(ogs_fsm_t *s, idsf_event_t *e);
// void idsf_nf_state_final(ogs_fsm_t *s, idsf_event_t *e);
// void idsf_nf_state_will_register(ogs_fsm_t *s, idsf_event_t *e);
// void idsf_nf_state_registered(ogs_fsm_t *s, idsf_event_t *e);
// void idsf_nf_state_de_registered(ogs_fsm_t *s, idsf_event_t *e);
// void idsf_nf_state_exception(ogs_fsm_t *s, idsf_event_t *e);

#define idsf_sm_debug(__pe) \
    ogs_debug("%s(): %s", __func__, idsf_event_get_name(__pe))

#ifdef __cplusplus
}
#endif

#endif /* IDSF_SM_H */