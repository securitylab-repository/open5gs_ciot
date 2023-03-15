/*
    created by le linh
    based on pcf, ausf
*/

#ifndef IDSF_NNRF_HANDLER_H
#define IDSF_NNRF_HANDLER_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

void idsf_nnrf_handle_nf_discover(
        ogs_sbi_xact_t *xact, ogs_sbi_message_t *recvmsg);

#ifdef __cplusplus
}
#endif

#endif /* IDSF_NNRF_HANDLER_H */
