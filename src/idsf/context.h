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

#ifdef __cplusplus
extern "C" {
#endif


extern int __idsf_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __idsf_log_domain

typedef struct idsf_context_s {
    int dummy;
} idsf_context_t;

void idsf_context_init(void);
void idsf_context_final(void);
idsf_context_t *idsf_self(void);

int idsf_context_parse_config(void);


#ifdef __cplusplus
}
#endif

#endif /* IDSF_CONTEXT_H */
