/*
    created by le linh
    created based on smf/app.c and amf/app.c
    Intrusion Detection System as Funtion (IDSF)
*/
#include "ogs-app.h"

int app_initialize(const char *const argv[])
{
    int rv;

    rv = idsf_initialize();
    if (rv != OGS_OK) {
        ogs_error("Failed to intialize IDSF");
        return rv;
    }
    ogs_info("IDSF initialize...done");

    return OGS_OK;
}

void app_terminate(void)
{
    idsf_terminate();
    ogs_info("IDSF terminate...done");