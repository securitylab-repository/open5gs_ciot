/*
    created by le linh
    based on pcf and ausf
*/

#include "sbi-path.h"
#include "context.h"

static idsf_context_t self;

int __idsf_log_domain;

static int context_initialized = 0;

void idsf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize IDSF context */
    memset(&self, 0, sizeof(idsf_context_t));
    
    ogs_log_install_domain(&__idsf_log_domain, "idsf", ogs_core()->log.level);

    context_initialized = 1;
}

void idsf_context_final(void)
{
    ogs_assert(context_initialized == 1);

    context_initialized = 0;
}

idsf_context_t *idsf_self(void)
{
    return &self;
}

static int idsf_context_prepare(void)
{
    return OGS_OK;
}

static int idsf_context_validation(void)
{
    return OGS_OK;
}

int idsf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    //note: create yaml file 
    document = ogs_app()->document;
    ogs_assert(document);

    rv = idsf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "idsf")) {
            ogs_yaml_iter_t idsf_iter;
            ogs_yaml_iter_recurse(&root_iter, &idsf_iter);
            while (ogs_yaml_iter_next(&idsf_iter)) {
                const char *idsf_key = ogs_yaml_iter_key(&idsf_iter);
                ogs_assert(idsf_key);
                if (!strcmp(idsf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(idsf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(idsf_key, "discovery")) {
                    /* handle config in sbi library */
                } else
                    ogs_warn("unknown key `%s`", idsf_key);
            }
        }
    }

    rv = idsf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}