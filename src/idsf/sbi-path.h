/* 
    created by le linh
    based on similar component of pcf,nrf,ausf
*/

#ifndef IDSF_SBI_PATH_H
#define IDSF_SBI_PATH_H

#include "nnrf-build.h"

#ifdef __cplusplus
extern "C" {
#endif

int idsf_sbi_open(void);
void idsf_sbi_close(void);

bool idsf_nnrf_nfm_send_nf_register(ogs_sbi_nf_instance_t *nf_instance);

bool idsf_sbi_send(ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_xact_t *xact);

#ifdef __cplusplus
}
#endif

#endif /* IDSF_SBI_PATH_H */