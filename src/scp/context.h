/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SCP_CONTEXT_H
#define SCP_CONTEXT_H

#include "ogs-sbi.h"
#include "ogs-app.h"

#include "timer.h"
#include "scp-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __scp_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __scp_log_domain

typedef struct scp_context_s {
    ogs_hash_t          *ipv4addr_hash;
    ogs_hash_t          *ipv6prefix_hash;

    ogs_list_t          sess_list;
} scp_context_t;

#define SCP_NF_INSTANCE_CLEAR(_cAUSE, _nFInstance) \
    do { \
        ogs_assert(_nFInstance); \
        if ((_nFInstance)->reference_count == 1) { \
            ogs_info("[%s] (%s) NF removed", (_nFInstance)->id, (_cAUSE)); \
            scp_nf_fsm_fini((_nFInstance)); \
        } else { \
            /* There is an assocation with other context */ \
            ogs_info("[%s:%d] (%s) NF suspended", \
                    _nFInstance->id, _nFInstance->reference_count, (_cAUSE)); \
            OGS_FSM_TRAN(&_nFInstance->sm, scp_nf_state_de_registered); \
            ogs_fsm_dispatch(&_nFInstance->sm, NULL); \
        } \
        ogs_sbi_nf_instance_remove(_nFInstance); \
    } while(0)

typedef struct scp_sess_s scp_sess_t;

typedef struct scp_sess_s {
    ogs_sbi_object_t sbi;

    char *binding_id;

    char *supi;
    char *gpsi;

    char *ipv4addr_string;
    char *ipv6prefix_string;

    uint32_t ipv4addr;
    struct {
        uint8_t len;
        uint8_t addr6[OGS_IPV6_LEN];
    } ipv6prefix;

    ogs_s_nssai_t s_nssai;
    char *dnn;

    /* PCF address information */
    char *pcf_fqdn;

    int num_of_pcf_ip;
    struct {
        char *addr;
        char *addr6;
        int port;
    } pcf_ip[OGS_SBI_MAX_NUM_OF_IP_ADDRESS];

    /* SBI Features */
    uint64_t management_features;

} scp_sess_t;

void scp_context_init(void);
void scp_context_final(void);
scp_context_t *scp_self(void);

int scp_context_parse_config(void);

scp_sess_t *scp_sess_add_by_snssai_and_dnn(ogs_s_nssai_t *s_nssai, char *dnn);
void scp_sess_remove(scp_sess_t *sess);
void scp_sess_remove_all(void);

bool scp_sess_set_ipv4addr(scp_sess_t *sess, char *ipv4addr);
bool scp_sess_set_ipv6prefix(scp_sess_t *sess, char *ipv6prefix);

scp_sess_t *scp_sess_find(uint32_t index);
scp_sess_t *scp_sess_find_by_snssai_and_dnn(ogs_s_nssai_t *s_nssai, char *dnn);
scp_sess_t *scp_sess_find_by_binding_id(char *binding_id);
scp_sess_t *scp_sess_find_by_ipv4addr(char *ipv4addr_string);
scp_sess_t *scp_sess_find_by_ipv6prefix(char *ipv6prefix_string);

void scp_sess_select_nf(scp_sess_t *sess, OpenAPI_nf_type_e nf_type);

#ifdef __cplusplus
}
#endif

#endif /* SCP_CONTEXT_H */
