/* 
    created by le linh
    based on similar component of amf,smf,pcf
    for interact with other function
    modified based on ausf
*/

#include "sbi-path.h"


static ogs_thread_t *thread;
static void idsf_main(void *data);
static int initialized = 0;

int idsf_initialize()
{
    int rv;

    // ogs_gtp_context_init(OGS_MAX_NUM_OF_GTPU_RESOURCE);

    ogs_sbi_context_init();
  
    // context.c
    idsf_context_init();

    // rv = ogs_gtp_xact_init();
    // if (rv != OGS_OK) return rv;

    //announce nrf - need check
    rv = ogs_sbi_context_parse_config("idsf", "nrf","scp");
    if (rv != OGS_OK) return rv;
    
    // YAML config file
    rv = idsf_context_parse_config();
    if (rv != OGS_OK) return rv;

    rv = ogs_log_config_domain(
            ogs_app()->logger.domain, ogs_app()->logger.level);
    if (rv != OGS_OK) return rv;

    // rv = idsf_gtp_open();
    // if (rv != OGS_OK) return rv;

    // sbi-path.c
    rv = idsf_sbi_open();
    if (rv != OGS_OK) return rv;

    thread = ogs_thread_create(idsf_main, NULL);
    if (!thread) return OGS_ERROR;

    initialized = 1;

    return OGS_OK;
}

static ogs_timer_t *t_termination_holding = NULL;

static void event_termination(void)
{
    ogs_sbi_nf_instance_t *nf_instance = NULL;

    /* Sending NF Instance De-registeration to NRF - nf-sm.c*/
    ogs_list_for_each(&ogs_sbi_self()->nf_instance_list, nf_instance)
        ogs_sbi_nf_fsm_fini(nf_instance);

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
// modified based on ausf
void idsf_terminate(void)
{
    if (!initialized) return;

    /* Daemon terminating */
    event_termination();
    ogs_thread_destroy(thread);
    ogs_timer_delete(t_termination_holding);

    //sbi-path.c
    idsf_sbi_close();
    // idsf_gtp_close();

    // context.c
    idsf_context_final();

    ogs_sbi_context_final();
    // ogs_gtp_context_final();

    // ogs_gtp_xact_final();

}

// based on pcf/init.c
static void idsf_main(void *data)
{
    ogs_fsm_t idsf_sm;
    int rv;

    // idsf-sm.c
    // ogs_fsm_create(&idsf_sm, idsf_state_initial, idsf_state_final);
    ogs_fsm_init(&idsf_sm, idsf_state_initial,idsf_state_final,0);

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
            ogs_event_free(e);
        }
    }
done:

    ogs_fsm_fini(&idsf_sm, 0);
}
