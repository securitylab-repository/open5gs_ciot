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

// void idsf_nnrf_handle_nf_register(
//         ogs_sbi_nf_instance_t *nf_instance, ogs_sbi_message_t *recvmsg);
// void idsf_nnrf_handle_nf_status_subscribe(
//         ogs_sbi_subscription_t *subscription, ogs_sbi_message_t *recvmsg);

// bool idsf_nnrf_handle_nf_status_notify(
//         ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg);

void idsf_nnrf_handle_nf_discover(
        ogs_sbi_xact_t *xact, ogs_sbi_message_t *recvmsg);

#ifdef __cplusplus
}
#endif

#endif /* IDSF_NNRF_HANDLER_H */
