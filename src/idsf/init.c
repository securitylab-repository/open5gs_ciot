// created by le linh
// based on similar component of amf,smf,pcf

// for interact with other function
#include "sbi-path.h"

static ogs_thread_t *thread;
static void idsf_main(void *data);
static int initialized = 0;

int idsf_initialize()
{
    int rv;

    ogs_sbi_context_init();

    // under construction 
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

