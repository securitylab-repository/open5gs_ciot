/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-PDU-Descriptions"
 * 	found in "../support/ngap-r17.3.0/38413-h30.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_NGAP_UnsuccessfulOutcome_H_
#define	_NGAP_UnsuccessfulOutcome_H_


#include <asn_application.h>

/* Including external dependencies */
#include "NGAP_ProcedureCode.h"
#include "NGAP_Criticality.h"
#include <ANY.h>
#include <asn_ioc.h>
#include "NGAP_AMFConfigurationUpdate.h"
#include "NGAP_AMFConfigurationUpdateAcknowledge.h"
#include "NGAP_AMFConfigurationUpdateFailure.h"
#include "NGAP_BroadcastSessionModificationRequest.h"
#include "NGAP_BroadcastSessionModificationResponse.h"
#include "NGAP_BroadcastSessionModificationFailure.h"
#include "NGAP_BroadcastSessionReleaseRequest.h"
#include "NGAP_BroadcastSessionReleaseResponse.h"
#include "NGAP_BroadcastSessionSetupRequest.h"
#include "NGAP_BroadcastSessionSetupResponse.h"
#include "NGAP_BroadcastSessionSetupFailure.h"
#include "NGAP_DistributionSetupRequest.h"
#include "NGAP_DistributionSetupResponse.h"
#include "NGAP_DistributionSetupFailure.h"
#include "NGAP_DistributionReleaseRequest.h"
#include "NGAP_DistributionReleaseResponse.h"
#include "NGAP_HandoverCancel.h"
#include "NGAP_HandoverCancelAcknowledge.h"
#include "NGAP_HandoverRequired.h"
#include "NGAP_HandoverCommand.h"
#include "NGAP_HandoverPreparationFailure.h"
#include "NGAP_HandoverRequest.h"
#include "NGAP_HandoverRequestAcknowledge.h"
#include "NGAP_HandoverFailure.h"
#include "NGAP_InitialContextSetupRequest.h"
#include "NGAP_InitialContextSetupResponse.h"
#include "NGAP_InitialContextSetupFailure.h"
#include "NGAP_MulticastSessionActivationRequest.h"
#include "NGAP_MulticastSessionActivationResponse.h"
#include "NGAP_MulticastSessionActivationFailure.h"
#include "NGAP_MulticastSessionDeactivationRequest.h"
#include "NGAP_MulticastSessionDeactivationResponse.h"
#include "NGAP_MulticastSessionUpdateRequest.h"
#include "NGAP_MulticastSessionUpdateResponse.h"
#include "NGAP_MulticastSessionUpdateFailure.h"
#include "NGAP_NGReset.h"
#include "NGAP_NGResetAcknowledge.h"
#include "NGAP_NGSetupRequest.h"
#include "NGAP_NGSetupResponse.h"
#include "NGAP_NGSetupFailure.h"
#include "NGAP_PathSwitchRequest.h"
#include "NGAP_PathSwitchRequestAcknowledge.h"
#include "NGAP_PathSwitchRequestFailure.h"
#include "NGAP_PDUSessionResourceModifyRequest.h"
#include "NGAP_PDUSessionResourceModifyResponse.h"
#include "NGAP_PDUSessionResourceModifyIndication.h"
#include "NGAP_PDUSessionResourceModifyConfirm.h"
#include "NGAP_PDUSessionResourceReleaseCommand.h"
#include "NGAP_PDUSessionResourceReleaseResponse.h"
#include "NGAP_PDUSessionResourceSetupRequest.h"
#include "NGAP_PDUSessionResourceSetupResponse.h"
#include "NGAP_PWSCancelRequest.h"
#include "NGAP_PWSCancelResponse.h"
#include "NGAP_RANConfigurationUpdate.h"
#include "NGAP_RANConfigurationUpdateAcknowledge.h"
#include "NGAP_RANConfigurationUpdateFailure.h"
#include "NGAP_UEContextModificationRequest.h"
#include "NGAP_UEContextModificationResponse.h"
#include "NGAP_UEContextModificationFailure.h"
#include "NGAP_UEContextReleaseCommand.h"
#include "NGAP_UEContextReleaseComplete.h"
#include "NGAP_UEContextResumeRequest.h"
#include "NGAP_UEContextResumeResponse.h"
#include "NGAP_UEContextResumeFailure.h"
#include "NGAP_UEContextSuspendRequest.h"
#include "NGAP_UEContextSuspendResponse.h"
#include "NGAP_UEContextSuspendFailure.h"
#include "NGAP_UERadioCapabilityCheckRequest.h"
#include "NGAP_UERadioCapabilityCheckResponse.h"
#include "NGAP_UERadioCapabilityIDMappingRequest.h"
#include "NGAP_UERadioCapabilityIDMappingResponse.h"
#include "NGAP_WriteReplaceWarningRequest.h"
#include "NGAP_WriteReplaceWarningResponse.h"
#include "NGAP_AMFCPRelocationIndication.h"
#include "NGAP_AMFStatusIndication.h"
#include "NGAP_BroadcastSessionReleaseRequired.h"
#include "NGAP_CellTrafficTrace.h"
#include "NGAP_ConnectionEstablishmentIndication.h"
#include "NGAP_DeactivateTrace.h"
#include "NGAP_DownlinkNASTransport.h"
#include "NGAP_DownlinkNonUEAssociatedNRPPaTransport.h"
#include "NGAP_DownlinkRANConfigurationTransfer.h"
#include "NGAP_DownlinkRANEarlyStatusTransfer.h"
#include "NGAP_DownlinkRANStatusTransfer.h"
#include "NGAP_DownlinkRIMInformationTransfer.h"
#include "NGAP_DownlinkUEAssociatedNRPPaTransport.h"
#include "NGAP_ErrorIndication.h"
#include "NGAP_HandoverNotify.h"
#include "NGAP_HandoverSuccess.h"
#include "NGAP_InitialUEMessage.h"
#include "NGAP_LocationReport.h"
#include "NGAP_LocationReportingControl.h"
#include "NGAP_LocationReportingFailureIndication.h"
#include "NGAP_MulticastGroupPaging.h"
#include "NGAP_NASNonDeliveryIndication.h"
#include "NGAP_OverloadStart.h"
#include "NGAP_OverloadStop.h"
#include "NGAP_Paging.h"
#include "NGAP_PDUSessionResourceNotify.h"
#include "NGAP_PrivateMessage.h"
#include "NGAP_PWSFailureIndication.h"
#include "NGAP_PWSRestartIndication.h"
#include "NGAP_RANCPRelocationIndication.h"
#include "NGAP_RerouteNASRequest.h"
#include "NGAP_RetrieveUEInformation.h"
#include "NGAP_RRCInactiveTransitionReport.h"
#include "NGAP_SecondaryRATDataUsageReport.h"
#include "NGAP_TraceFailureIndication.h"
#include "NGAP_TraceStart.h"
#include "NGAP_UEContextReleaseRequest.h"
#include "NGAP_UEInformationTransfer.h"
#include "NGAP_UERadioCapabilityInfoIndication.h"
#include "NGAP_UETNLABindingReleaseRequest.h"
#include "NGAP_UplinkNASTransport.h"
#include "NGAP_UplinkNonUEAssociatedNRPPaTransport.h"
#include "NGAP_UplinkRANConfigurationTransfer.h"
#include "NGAP_UplinkRANEarlyStatusTransfer.h"
#include "NGAP_UplinkRANStatusTransfer.h"
#include "NGAP_UplinkRIMInformationTransfer.h"
#include "NGAP_UplinkUEAssociatedNRPPaTransport.h"
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NGAP_UnsuccessfulOutcome__value_PR {
	NGAP_UnsuccessfulOutcome__value_PR_NOTHING,	/* No components present */
	NGAP_UnsuccessfulOutcome__value_PR_AMFConfigurationUpdateFailure,
	NGAP_UnsuccessfulOutcome__value_PR_BroadcastSessionModificationFailure,
	NGAP_UnsuccessfulOutcome__value_PR_BroadcastSessionSetupFailure,
	NGAP_UnsuccessfulOutcome__value_PR_DistributionSetupFailure,
	NGAP_UnsuccessfulOutcome__value_PR_HandoverPreparationFailure,
	NGAP_UnsuccessfulOutcome__value_PR_HandoverFailure,
	NGAP_UnsuccessfulOutcome__value_PR_InitialContextSetupFailure,
	NGAP_UnsuccessfulOutcome__value_PR_MulticastSessionActivationFailure,
	NGAP_UnsuccessfulOutcome__value_PR_MulticastSessionUpdateFailure,
	NGAP_UnsuccessfulOutcome__value_PR_NGSetupFailure,
	NGAP_UnsuccessfulOutcome__value_PR_PathSwitchRequestFailure,
	NGAP_UnsuccessfulOutcome__value_PR_RANConfigurationUpdateFailure,
	NGAP_UnsuccessfulOutcome__value_PR_UEContextModificationFailure,
	NGAP_UnsuccessfulOutcome__value_PR_UEContextResumeFailure,
	NGAP_UnsuccessfulOutcome__value_PR_UEContextSuspendFailure
} NGAP_UnsuccessfulOutcome__value_PR;

/* NGAP_UnsuccessfulOutcome */
typedef struct NGAP_UnsuccessfulOutcome {
	NGAP_ProcedureCode_t	 procedureCode;
	NGAP_Criticality_t	 criticality;
	struct NGAP_UnsuccessfulOutcome__value {
		NGAP_UnsuccessfulOutcome__value_PR present;
		union NGAP_UnsuccessfulOutcome__NGAP_value_u {
			NGAP_AMFConfigurationUpdateFailure_t	 AMFConfigurationUpdateFailure;
			NGAP_BroadcastSessionModificationFailure_t	 BroadcastSessionModificationFailure;
			NGAP_BroadcastSessionSetupFailure_t	 BroadcastSessionSetupFailure;
			NGAP_DistributionSetupFailure_t	 DistributionSetupFailure;
			NGAP_HandoverPreparationFailure_t	 HandoverPreparationFailure;
			NGAP_HandoverFailure_t	 HandoverFailure;
			NGAP_InitialContextSetupFailure_t	 InitialContextSetupFailure;
			NGAP_MulticastSessionActivationFailure_t	 MulticastSessionActivationFailure;
			NGAP_MulticastSessionUpdateFailure_t	 MulticastSessionUpdateFailure;
			NGAP_NGSetupFailure_t	 NGSetupFailure;
			NGAP_PathSwitchRequestFailure_t	 PathSwitchRequestFailure;
			NGAP_RANConfigurationUpdateFailure_t	 RANConfigurationUpdateFailure;
			NGAP_UEContextModificationFailure_t	 UEContextModificationFailure;
			NGAP_UEContextResumeFailure_t	 UEContextResumeFailure;
			NGAP_UEContextSuspendFailure_t	 UEContextSuspendFailure;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} value;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NGAP_UnsuccessfulOutcome_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_UnsuccessfulOutcome;
extern asn_SEQUENCE_specifics_t asn_SPC_NGAP_UnsuccessfulOutcome_specs_1;
extern asn_TYPE_member_t asn_MBR_NGAP_UnsuccessfulOutcome_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_UnsuccessfulOutcome_H_ */
#include <asn_internal.h>
