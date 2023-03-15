/*
    created by le linh
    based on nrf, pcf, ausf
*/

#include "event.h"

idsf_event_t *idsf_event_new(int id)
{
    idsf_event_t *e = NULL;

    e = ogs_event_size(id, sizeof(idsf_event_t));
    // ogs_pool_alloc(&pool, &e);
    ogs_assert(e);
    // memset(e, 0, sizeof(*e));

    e->h.id = id;

    return e;
}

const char *idsf_event_get_name(idsf_event_t *e)
{
    if (e == NULL)
        return OGS_FSM_NAME_INIT_SIG;

    switch (e->h.id) {
    case OGS_FSM_ENTRY_SIG: 
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG: 
        return OGS_FSM_NAME_EXIT_SIG;

    case OGS_EVENT_SBI_SERVER:
        return OGS_EVENT_NAME_SBI_SERVER;
    case OGS_EVENT_SBI_CLIENT:
        return OGS_EVENT_NAME_SBI_CLIENT;
    case OGS_EVENT_SBI_TIMER:
        return OGS_EVENT_NAME_SBI_TIMER;

    default: 
       break;
    }

    ogs_error("Unknown Event[%d]", e->h.id);
    return "UNKNOWN_EVENT";
}