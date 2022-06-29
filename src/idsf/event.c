/*
    created by le linh
    based on nrf, pcf, ausf
*/

#include "event.h"
#include "context.h"

static OGS_POOL(pool, idsf_event_t);

void idsf_event_init(void)
{
    ogs_pool_init(&pool, ogs_app()->pool.event);
}

void idsf_event_final(void)
{
    ogs_pool_final(&pool);
}

idsf_event_t *idsf_event_new(idsf_event_e id)
{
    idsf_event_t *e = NULL;

    ogs_pool_alloc(&pool, &e);
    ogs_assert(e);
    memset(e, 0, sizeof(*e));

    e->id = id;

    return e;
}

void idsf_event_free(idsf_event_t *e)
{
    ogs_assert(e);
    ogs_pool_free(&pool, e);
}

const char *idsf_event_get_name(idsf_event_t *e)
{
    if (e == NULL)
        return OGS_FSM_NAME_INIT_SIG;

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG: 
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG: 
        return OGS_FSM_NAME_EXIT_SIG;

    case IDSF_EVT_SBI_SERVER:
        return "AUSF_EVT_SBI_SERVER";
    case IDSF_EVT_SBI_CLIENT:
        return "AUSF_EVT_SBI_CLIENT";
    case IDSF_EVT_SBI_TIMER:
        return "AUSF_EVT_SBI_TIMER";

    default: 
       break;
    }

    return "UNKNOWN_EVENT";
}