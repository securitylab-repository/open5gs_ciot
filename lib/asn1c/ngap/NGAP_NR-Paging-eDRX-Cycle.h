/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r17.3.0/38413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_NGAP_NR_Paging_eDRX_Cycle_H_
#define	_NGAP_NR_Paging_eDRX_Cycle_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_NR_Paging_eDRX_Cycle {
	NGAP_NR_Paging_eDRX_Cycle_hfquarter	= 0,
	NGAP_NR_Paging_eDRX_Cycle_hfhalf	= 1,
	NGAP_NR_Paging_eDRX_Cycle_hf1	= 2,
	NGAP_NR_Paging_eDRX_Cycle_hf2	= 3,
	NGAP_NR_Paging_eDRX_Cycle_hf4	= 4,
	NGAP_NR_Paging_eDRX_Cycle_hf8	= 5,
	NGAP_NR_Paging_eDRX_Cycle_hf16	= 6,
	NGAP_NR_Paging_eDRX_Cycle_hf32	= 7,
	NGAP_NR_Paging_eDRX_Cycle_hf64	= 8,
	NGAP_NR_Paging_eDRX_Cycle_hf128	= 9,
	NGAP_NR_Paging_eDRX_Cycle_hf256	= 10,
	NGAP_NR_Paging_eDRX_Cycle_hf512	= 11,
	NGAP_NR_Paging_eDRX_Cycle_hf1024	= 12
	/*
	 * Enumeration is extensible
	 */
} e_NGAP_NR_Paging_eDRX_Cycle;

/* NGAP_NR-Paging-eDRX-Cycle */
typedef long	 NGAP_NR_Paging_eDRX_Cycle_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_NGAP_NR_Paging_eDRX_Cycle_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_NGAP_NR_Paging_eDRX_Cycle;
extern const asn_INTEGER_specifics_t asn_SPC_NGAP_NR_Paging_eDRX_Cycle_specs_1;
asn_struct_free_f NGAP_NR_Paging_eDRX_Cycle_free;
asn_struct_print_f NGAP_NR_Paging_eDRX_Cycle_print;
asn_constr_check_f NGAP_NR_Paging_eDRX_Cycle_constraint;
jer_type_encoder_f NGAP_NR_Paging_eDRX_Cycle_encode_jer;
per_type_decoder_f NGAP_NR_Paging_eDRX_Cycle_decode_aper;
per_type_encoder_f NGAP_NR_Paging_eDRX_Cycle_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_NR_Paging_eDRX_Cycle_H_ */
#include <asn_internal.h>
