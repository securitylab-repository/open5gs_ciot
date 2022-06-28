/* 
    created by le linh
    based on similar component of amf,smf,pcf
    for interact with other function
*/

#include "sbi-path.h"

static ogs_thread_t *thread;
static void idsf_main(void *data);
static int initialized = 0;

int idsf_initialize()
{
    int rv;

    ogs_sbi_context_init();

    // need definition - context.c 
    idsf_context_init();
    idsf_event_init();

    //announce nrf
    rv = ogs_sbi_context_parse_config("idsf", "nrf");
    if (rv != OGS_OK) return rv;
    
    rv = idsf_context_parse_config();
    if (rv != OGS_OK) return rv;
    // under construction 

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    // underconstruction
    rv = idsf_sbi_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(idsf_main, NULL);
    if (!thread) return OGS_ERROR;
    // underconstruction

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* Sending NF Instance De-registeration to NRF */
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance)
        idsf_nf_fsm_fini(nf_instance);

    /* Starting holding timer */
    t_termination_holding = ogs_timer_add(ogs_app()->timer_mgr, NULL, NULL);
    ogs_assert(t_termination_holding);
#define TERMINATION_HOLDING_TIME ogs_time_from_msec(300)
    ogs_timer_start(t_termination_holding, TERMINATION_HOLDING_TIME);

    /* Sending termination event to the queue */
    ogs_queue_term(ogs_app()->queue);
    ogs_pollset_notify(ogs_app()->pollset);
}

// based from pcf/init.c
void idsf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    //need creation
    idsf_sbi_close();

    //need creation
    idsf_context_final();
    ogs_sbi_context_final();

    //need creation
    idsf_event_final(); /* Destroy event */
}

// based on pcf/init.c
static void idsf_main(void *data)
{
    ogs_fsm_t idsf_sm;
    int rv;

    //need creation for param
    ogs_fsm_create(&idsf_sm, idsf_state_initial, idsf_state_final);
    ogs_fsm_init(&idsf_sm, 0);

    for ( ;; ) {
        ogs_pollset_poll(ogs_app()->pollset,
                ogs_timer_mgr_next(ogs_app()->timer_mgr));

        /*
         * After ogs_pollset_poll(), ogs_timer_mgr_expire() must be called.
         *
         * The reason is why ogs_timer_mgr_next() can get the corrent value
         * when ogs_timer_stop() is called internally in ogs_timer_mgr_expire().
         *
         * You should not use event-queue before ogs_timer_mgr_expire().
         * In this case, ogs_timer_mgr_expire() does not work
         * because 'if rv == OGS_DONE' statement is exiting and
         * not calling ogs_timer_mgr_expire().
         */
        ogs_timer_mgr_expire(ogs_app()->timer_mgr);

        for ( ;; ) {
            idsf_event_t *e = NULL;

            rv = ogs_queue_trypop(ogs_app()->queue, (void**)&e);
            ogs_assert(rv != OGS_ERROR);

            if (rv == OGS_DONE)
                goto done;

            if (rv == OGS_RETRY)
                break;

            ogs_assert(e);
            ogs_fsm_dispatch(&idsf_sm, e);
            idsf_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&idsf_sm, 0);
    ogs_fsm_delete(&idsf_sm);
}
