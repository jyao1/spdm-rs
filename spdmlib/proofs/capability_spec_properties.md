# SPDM Capability Spec Properties (DSP0274)

Formal verification properties derived purely from DMTF DSP0274 specification text.
These properties are tool-agnostic and can be verified by any formal verification
tool (Kani, Verus, etc.).

## Table 11: GET_CAPABILITIES Request

| ID | Property | Spec Source |
|----|----------|-------------|
| REQ_P1 | Param1 Bit 0 → Requester CHUNK_CAP=1 | "If the Requester does not support the Large SPDM message transfer mechanism (CHUNK_CAP=0), this bit shall be 0." |
| REQ_P2 | Param1 Bit 0 → Responder CHUNK_CAP=1 | "only allowed if both the Requester and Responder support the Large SPDM message transfer mechanism (CHUNK_CAP=1)". "If...Responder does not support...(CHUNK_CAP=0), the Responder shall send an ERROR message of ErrorCode=InvalidRequest." |
| REQ_P3 | DataTransferSize >= MinDataTransferSize (42) | |
| REQ_P4 | MaxSPDMmsgSize >= DataTransferSize | |
| REQ_P5 | If Requester CHUNK_CAP=0, MaxSPDMmsgSize SHALL equal DataTransferSize | |

## Table 12: CAPABILITIES Response

| ID | Property | Spec Source |
|----|----------|-------------|
| RSP_P1 | Param1 Bit 0: if Responder CHUNK_CAP=0, this bit SHALL be 0 | "If the Responder does not support this extended capability or does not support the Large SPDM message transfer mechanism (CHUNK_CAP=0), this bit shall be 0." |
| RSP_P2 | DataTransferSize >= MinDataTransferSize (42) | |
| RSP_P3 | MaxSPDMmsgSize >= DataTransferSize | |
| RSP_P4 | If Responder CHUNK_CAP=0, MaxSPDMmsgSize SHALL equal DataTransferSize | |
| RSP_P5 | SupportedAlgorithms block SHALL be present if Param1 Bit 0 set | Feature: response encode shall include it when applicable |

## Table 13: Requester Flags

| ID | Property | Spec Source |
|----|----------|-------------|
| REQF_P1 | KEY_EX_CAP → (ENCRYPT_CAP ∨ MAC_CAP) | "If set, ENCRYPT_CAP or MAC_CAP shall be set." |
| REQF_P2 | PSK_CAP → (ENCRYPT_CAP ∨ MAC_CAP) | "If supported, ENCRYPT_CAP or MAC_CAP shall be set." |
| REQF_P3 | PSK_CAP: only 00b and 01b valid (10b and 11b reserved) | "10b and 11b. Reserved." |
| REQF_P4 | HANDSHAKE_IN_THE_CLEAR_CAP: PSK_CAP=01b ∧ KEY_EX_CAP=0 → HITC=0 | "If the Requester supports Pre-Shared Keys (PSK_CAP is 01b) and does not support asymmetric key exchange (KEY_EX_CAP is 0b), then this bit shall be zero." |
| REQF_P5 | HANDSHAKE_IN_THE_CLEAR_CAP → (ENCRYPT_CAP ∨ MAC_CAP) | "If the Requester does not support encryption and message authentication, then this bit shall be zero." |
| REQF_P6 | PUB_KEY_ID_CAP → ¬CERT_CAP ∧ ¬MULTI_KEY_CAP | "the CERT_CAP and MULTI_KEY_CAP of the Requester shall be 0." |
| REQF_P7 | EP_INFO_CAP: 11b reserved | EP_INFO_CAP_NO_SIG and EP_INFO_CAP_SIG mutually exclusive |
| REQF_P8 | MULTI_KEY_CAP: 11b reserved | MULTI_KEY_CAP_ONLY and MULTI_KEY_CAP_CONN_SEL mutually exclusive |
| REQF_P9 | ENCRYPT_CAP → (KEY_EX_CAP ∨ PSK_CAP) | Prose after Table 16: "ENCRYPT_CAP is set but both KEY_EX_CAP and PSK_CAP are cleared" is an "illegal capability flag combination" |
| REQF_P10 | MAC_CAP → (KEY_EX_CAP ∨ PSK_CAP) | Same reasoning as REQF_P9. |
| REQF_P11 | HBEAT_CAP → (KEY_EX_CAP ∨ PSK_CAP) | HEARTBEAT operates within sessions only. |
| REQF_P12 | KEY_UPD_CAP → (KEY_EX_CAP ∨ PSK_CAP) | KEY_UPDATE operates within sessions only. |
| REQF_P13 | EVENT_CAP → (KEY_EX_CAP ∨ PSK_CAP) [v1.3+] | "event mechanism provides a framework for the asynchronous notification of events over a secure session" |

## Table 15: Responder Flags

| ID | Property | Spec Source |
|----|----------|-------------|
| RSPF_P1 | MEAS_CAP: 11b reserved | "11b. Reserved." |
| RSPF_P2 | MEAS_FRESH_CAP → (MEAS_CAP ≠ 00b) | Only valid if MEAS_CAP_NO_SIG or MEAS_CAP_SIG is set. |
| RSPF_P3 | KEY_EX_CAP → (ENCRYPT_CAP ∨ MAC_CAP) | "If set, ENCRYPT_CAP or MAC_CAP shall be set." |
| RSPF_P4 | PSK_CAP → (ENCRYPT_CAP ∨ MAC_CAP) | "If supported, ENCRYPT_CAP or MAC_CAP shall be set." |
| RSPF_P5 | PSK_CAP: 11b reserved | "11b. Reserved." |
| RSPF_P6 | ENCRYPT_CAP → (KEY_EX_CAP ∨ PSK_CAP) | "If set, PSK_CAP or KEY_EX_CAP shall be set accordingly." |
| RSPF_P7 | MAC_CAP → (KEY_EX_CAP ∨ PSK_CAP) | "If set, PSK_CAP or KEY_EX_CAP shall be set accordingly." |
| RSPF_P8 | HANDSHAKE_IN_THE_CLEAR_CAP → KEY_EX_CAP | "If set, KEY_EX_CAP shall also be set." |
| RSPF_P9 | HANDSHAKE_IN_THE_CLEAR_CAP: PSK ∧ ¬KEY_EX → HITC=0 | "If the Responder supports Pre-Shared Keys (PSK_CAP is 01b) and does not support asymmetric key exchange (KEY_EX_CAP is 0b), then this bit shall be zero." |
| RSPF_P10 | HANDSHAKE_IN_THE_CLEAR_CAP → (ENCRYPT_CAP ∨ MAC_CAP) | "If the Responder does not support encryption and message authentication, then this bit shall be zero." |
| RSPF_P11 | PUB_KEY_ID_CAP → ¬CERT_CAP ∧ ¬ALIAS_CERT_CAP ∧ ¬MULTI_KEY_CAP | "the CERT_CAP, ALIAS_CERT_CAP, and MULTI_KEY_CAP shall be 0." |
| RSPF_P12 | ALIAS_CERT_CAP → CERT_CAP | "If set, the Responder shall use the AliasCert model" (implies CERT) |
| RSPF_P13 | CSR_CAP → SET_CERT_CAP | "If this bit is set, SET_CERT_CAP shall be set." |
| RSPF_P14 | CERT_INSTALL_RESET_CAP → SET_CERT_CAP | "If this bit is set, SET_CERT_CAP shall be set and CSR_CAP can be set." |
| RSPF_P15 | EP_INFO_CAP: 11b reserved | |
| RSPF_P16 | MULTI_KEY_CAP: 11b reserved | |
| RSPF_P17 | MULTI_KEY_CAP → GET_KEY_PAIR_INFO_CAP | "If the Responder sets MULTI_KEY_CAP, this bit shall also be set." |
| RSPF_P18 | SET_KEY_PAIR_RESET_CAP → SET_KEY_PAIR_INFO_CAP | "If this bit is set, SET_KEY_PAIR_INFO_CAP shall be set." |
| RSPF_P19 | HBEAT_CAP → (KEY_EX_CAP ∨ PSK_CAP) | Session-only capability. |
| RSPF_P20 | KEY_UPD_CAP → (KEY_EX_CAP ∨ PSK_CAP) | Session-only capability. |
| RSPF_P21 | EVENT_CAP → (KEY_EX_CAP ∨ PSK_CAP) [v1.3+] | Events require secure session. |

## Table 16: Responder ExtFlags

No cross-field constraints specified for SLOT_MGMT_CAP.

## Feature Requirements

| ID | Property | Spec Source |
|----|----------|-------------|
| FEAT_F1 | Responder SHALL include SupportedAlgorithms block when requested and supported | Table 12, Param1 Bit 0 response |
| FEAT_F2 | Responder SHALL set Param1 Bit 0 in response when applicable | |
| FEAT_F3 | Requester SHALL validate Param1 in CAPABILITIES response | |
