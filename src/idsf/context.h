/*
    created by le linh
    based on pcf, nrf and ausf context
*/

#ifndef IDSF_CONTEXT_H
#define IDSF_CONTEXT_H

#include "ogs-app.h"
#include "ogs-sbi.h"

// is sm short for session management or session main ?
#include "idsf-sm.h"
// #include "timer.h"

#ifdef __cplusplus
extern "C" {
#endif

// #define MAX_NUM_OF_SERVED_GUAMI     8

extern int __idsf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __idsf_log_domain

typedef struct idsf_context_s {
    int dummy;
} idsf_context_t;

/*
for notify NRF
#define IDSF_NF_INSTANCE_CLEAR(_cAUSE, _nFInstance) \
    do { \
        ogs_assert(_nFInstance); \
        if ((_nFInstance)->reference_count == 1) { \
            ogs_info("[%s] (%s) NF removed", (_nFInstance)->id, (_cAUSE)); \
            idsf_nf_fsm_fini((_nFInstance)); \
        } else { \
            // There is an assocation with other context \
            ogs_info("[%s:%d] (%s) NF suspended", \
                    _nFInstance->id, _nFInstance->reference_count, (_cAUSE)); \
            OGS_FSM_TRAN(&_nFInstance->sm, idsf_nf_state_de_registered); \
            ogs_fsm_dispatch(&_nFInstance->sm, NULL); \
        } \
        ogs_sbi_nf_instance_remove(_nFInstance); \
    } while(0)
*/

void idsf_context_init(void);
void idsf_context_final(void);
idsf_context_t *idsf_self(void);

int idsf_context_parse_config(void);


#ifdef __cplusplus
}
#endif

#endif /* IDSF_CONTEXT_H */
