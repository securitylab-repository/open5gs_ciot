/*
    created by le linh
    based on nrf, pcf, ausf
*/

#ifndef IDSF_EVENT_H
#define IDSF_EVENT_H

#include "ogs-proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct idsf_event_s {
    ogs_event_t h;
} idsf_event_t;

OGS_STATIC_ASSERT(OGS_EVENT_SIZE >= sizeof(idsf_event_t));


idsf_event_t *idsf_event_new(int id);

const char *idsf_event_get_name(idsf_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* IDSF_EVENT_H */