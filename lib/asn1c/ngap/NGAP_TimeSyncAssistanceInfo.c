/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r17.3.0/38413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#include "NGAP_TimeSyncAssistanceInfo.h"

#include "NGAP_ProtocolExtensionContainer.h"
/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
static int
memb_NGAP_uUTimeSyncErrorBudget_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1L && value <= 1000000L)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_PER_type_NGAP_timeDistributionIndication_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  1,  1,  0,  1 }	/* (0..1,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_PER_memb_NGAP_uUTimeSyncErrorBudget_constr_6 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  20, -1,  1,  1000000 }	/* (1..1000000,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_NGAP_timeDistributionIndication_value2enum_2[] = {
	{ 0,	7,	"enabled" },
	{ 1,	8,	"disabled" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_NGAP_timeDistributionIndication_enum2value_2[] = {
	1,	/* disabled(1) */
	0	/* enabled(0) */
	/* This list is extensible */
};
static const asn_INTEGER_specifics_t asn_SPC_NGAP_timeDistributionIndication_specs_2 = {
	asn_MAP_NGAP_timeDistributionIndication_value2enum_2,	/* "tag" => N; sorted by tag */
	asn_MAP_NGAP_timeDistributionIndication_enum2value_2,	/* N => "tag"; sorted by N */
	2,	/* Number of elements in the maps */
	3,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_NGAP_timeDistributionIndication_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_NGAP_timeDistributionIndication_2 = {
	"timeDistributionIndication",
	"timeDistributionIndication",
	&asn_OP_NativeEnumerated,
	asn_DEF_NGAP_timeDistributionIndication_tags_2,
	sizeof(asn_DEF_NGAP_timeDistributionIndication_tags_2)
		/sizeof(asn_DEF_NGAP_timeDistributionIndication_tags_2[0]) - 1, /* 1 */
	asn_DEF_NGAP_timeDistributionIndication_tags_2,	/* Same as above */
	sizeof(asn_DEF_NGAP_timeDistributionIndication_tags_2)
		/sizeof(asn_DEF_NGAP_timeDistributionIndication_tags_2[0]), /* 2 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_NGAP_timeDistributionIndication_constr_2,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_NGAP_timeDistributionIndication_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_NGAP_TimeSyncAssistanceInfo_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct NGAP_TimeSyncAssistanceInfo, timeDistributionIndication),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_timeDistributionIndication_2,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"timeDistributionIndication"
		},
	{ ATF_POINTER, 2, offsetof(struct NGAP_TimeSyncAssistanceInfo, uUTimeSyncErrorBudget),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			&asn_PER_memb_NGAP_uUTimeSyncErrorBudget_constr_6,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			memb_NGAP_uUTimeSyncErrorBudget_constraint_1
		},
		0, 0, /* No default value */
		"uUTimeSyncErrorBudget"
		},
	{ ATF_POINTER, 1, offsetof(struct NGAP_TimeSyncAssistanceInfo, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NGAP_ProtocolExtensionContainer_11905P331,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_NGAP_TimeSyncAssistanceInfo_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_NGAP_TimeSyncAssistanceInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeDistributionIndication */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* uUTimeSyncErrorBudget */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* iE-Extensions */
};
asn_SEQUENCE_specifics_t asn_SPC_NGAP_TimeSyncAssistanceInfo_specs_1 = {
	sizeof(struct NGAP_TimeSyncAssistanceInfo),
	offsetof(struct NGAP_TimeSyncAssistanceInfo, _asn_ctx),
	asn_MAP_NGAP_TimeSyncAssistanceInfo_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_NGAP_TimeSyncAssistanceInfo_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_NGAP_TimeSyncAssistanceInfo = {
	"TimeSyncAssistanceInfo",
	"TimeSyncAssistanceInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1,
	sizeof(asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1)
		/sizeof(asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1[0]), /* 1 */
	asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1)
		/sizeof(asn_DEF_NGAP_TimeSyncAssistanceInfo_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_NGAP_TimeSyncAssistanceInfo_1,
	3,	/* Elements count */
	&asn_SPC_NGAP_TimeSyncAssistanceInfo_specs_1	/* Additional specs */
};

