// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Kani formal verification proofs for SPDM capability validation (DSP0274).
//!
//! These proofs call the REAL implementation functions directly — no models.
//! Each harness verifies a spec property from Tables 11-15 against the actual code.
//!
//! Verified functions:
//!   - `validate_request_capability_flags(flags: u32) -> bool`
//!   - `validate_request_sizes(data_transfer_size: u32, max_spdm_msg_size: u32, has_chunk_cap: bool) -> bool`
//!
//! To run: `cargo kani --harness <harness_name>`
//! Or run all: `cargo kani`

use spdmlib::protocol::capability_validation::*;

// ############################################################################
// Table 13 Properties: Requester Capability Flags
// ############################################################################

/// REQF_P1: KEY_EX_CAP → (ENCRYPT_CAP ∨ MAC_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p1_key_ex_requires_encrypt_or_mac() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & KEY_EX_CAP != 0 {
            assert!(
                flags & ENCRYPT_CAP != 0 || flags & MAC_CAP != 0,
                "REQF_P1: KEY_EX_CAP requires ENCRYPT_CAP or MAC_CAP"
            );
        }
    }
}

/// REQF_P2: PSK_CAP → (ENCRYPT_CAP ∨ MAC_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p2_psk_requires_encrypt_or_mac() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & PSK_CAP != 0 {
            assert!(
                flags & ENCRYPT_CAP != 0 || flags & MAC_CAP != 0,
                "REQF_P2: PSK_CAP requires ENCRYPT_CAP or MAC_CAP"
            );
        }
    }
}

/// REQF_P3: PSK_RSVD shall not be set
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p3_psk_reserved_bits() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        assert!(
            flags & PSK_RSVD == 0,
            "REQF_P3: PSK_CAP 10b/11b reserved"
        );
    }
}

/// REQF_P4: PSK_CAP=1 ∧ KEY_EX_CAP=0 → HANDSHAKE_IN_THE_CLEAR_CAP=0
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p4_psk_no_key_ex_no_hitc() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & PSK_CAP != 0 && flags & KEY_EX_CAP == 0 {
            assert!(
                flags & HANDSHAKE_IN_THE_CLEAR_CAP == 0,
                "REQF_P4: PSK without KEY_EX requires HITC=0"
            );
        }
    }
}

/// REQF_P5: HANDSHAKE_IN_THE_CLEAR_CAP → (ENCRYPT_CAP ∨ MAC_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p5_hitc_requires_encrypt_or_mac() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & HANDSHAKE_IN_THE_CLEAR_CAP != 0 {
            assert!(
                flags & ENCRYPT_CAP != 0 || flags & MAC_CAP != 0,
                "REQF_P5: HITC requires ENCRYPT_CAP or MAC_CAP"
            );
        }
    }
}

/// REQF_P6: PUB_KEY_ID_CAP → ¬CERT_CAP ∧ ¬MULTI_KEY_CAP
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p6_pub_key_id_excludes_cert_and_multi_key() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & PUB_KEY_ID_CAP != 0 {
            assert!(flags & CERT_CAP == 0, "REQF_P6: PUB_KEY_ID requires CERT_CAP=0");
            assert!(
                flags & MULTI_KEY_CAP_ONLY == 0 && flags & MULTI_KEY_CAP_CONN_SEL == 0,
                "REQF_P6: PUB_KEY_ID requires MULTI_KEY_CAP=0"
            );
        }
    }
}

/// REQF_P7: EP_INFO_CAP 11b reserved
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p7_ep_info_not_both() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        assert!(
            !(flags & EP_INFO_CAP_NO_SIG != 0 && flags & EP_INFO_CAP_SIG != 0),
            "REQF_P7: EP_INFO_CAP 11b reserved"
        );
    }
}

/// REQF_P8: MULTI_KEY_CAP 11b reserved
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p8_multi_key_not_both() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        assert!(
            !(flags & MULTI_KEY_CAP_ONLY != 0 && flags & MULTI_KEY_CAP_CONN_SEL != 0),
            "REQF_P8: MULTI_KEY_CAP 11b reserved"
        );
    }
}

/// REQF_P9: ENCRYPT_CAP → (KEY_EX_CAP ∨ PSK_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p9_encrypt_requires_session() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & ENCRYPT_CAP != 0 {
            assert!(
                flags & KEY_EX_CAP != 0 || flags & PSK_CAP != 0,
                "REQF_P9: ENCRYPT_CAP requires KEY_EX_CAP or PSK_CAP"
            );
        }
    }
}

/// REQF_P10: MAC_CAP → (KEY_EX_CAP ∨ PSK_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p10_mac_requires_session() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & MAC_CAP != 0 {
            assert!(
                flags & KEY_EX_CAP != 0 || flags & PSK_CAP != 0,
                "REQF_P10: MAC_CAP requires KEY_EX_CAP or PSK_CAP"
            );
        }
    }
}

/// REQF_P11: HBEAT_CAP → (KEY_EX_CAP ∨ PSK_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p11_hbeat_requires_session() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & HBEAT_CAP != 0 {
            assert!(
                flags & KEY_EX_CAP != 0 || flags & PSK_CAP != 0,
                "REQF_P11: HBEAT_CAP requires KEY_EX_CAP or PSK_CAP"
            );
        }
    }
}

/// REQF_P12: KEY_UPD_CAP → (KEY_EX_CAP ∨ PSK_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p12_key_upd_requires_session() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & KEY_UPD_CAP != 0 {
            assert!(
                flags & KEY_EX_CAP != 0 || flags & PSK_CAP != 0,
                "REQF_P12: KEY_UPD_CAP requires KEY_EX_CAP or PSK_CAP"
            );
        }
    }
}

/// REQF_P13: EVENT_CAP → (KEY_EX_CAP ∨ PSK_CAP)
#[cfg(kani)]
#[kani::proof]
fn verify_reqf_p13_event_requires_session() {
    let flags: u32 = kani::any();
    if validate_request_capability_flags(flags) {
        if flags & EVENT_CAP != 0 {
            assert!(
                flags & KEY_EX_CAP != 0 || flags & PSK_CAP != 0,
                "REQF_P13: EVENT_CAP requires KEY_EX_CAP or PSK_CAP"
            );
        }
    }
}

// ############################################################################
// Table 11 Properties: Size Validation (GET_CAPABILITIES request)
// ############################################################################

/// REQ_P3: DataTransferSize >= 42
#[cfg(kani)]
#[kani::proof]
fn verify_req_p3_data_transfer_size_minimum() {
    let dts: u32 = kani::any();
    let mms: u32 = kani::any();
    let chunk: bool = kani::any();
    if validate_request_sizes(dts, mms, chunk) {
        assert!(dts >= 42, "REQ_P3: DataTransferSize >= 42");
    }
}

/// REQ_P4: MaxSPDMmsgSize >= DataTransferSize
#[cfg(kani)]
#[kani::proof]
fn verify_req_p4_max_msg_size_gte_transfer() {
    let dts: u32 = kani::any();
    let mms: u32 = kani::any();
    let chunk: bool = kani::any();
    if validate_request_sizes(dts, mms, chunk) {
        assert!(mms >= dts, "REQ_P4: MaxSPDMmsgSize >= DataTransferSize");
    }
}

/// REQ_P5: If CHUNK_CAP=0, MaxSPDMmsgSize SHALL equal DataTransferSize
#[cfg(kani)]
#[kani::proof]
fn verify_req_p5_no_chunk_msg_size_equals_transfer() {
    let dts: u32 = kani::any();
    let mms: u32 = kani::any();
    let chunk: bool = kani::any();
    if validate_request_sizes(dts, mms, chunk) {
        if !chunk {
            assert!(mms == dts, "REQ_P5: Without CHUNK_CAP, MaxSPDMmsgSize == DataTransferSize");
        }
    }
}
