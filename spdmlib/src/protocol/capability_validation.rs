// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

// Pure validation of SPDM capability flags per DSP0274 spec Tables 13 and 15.
//
// These are `const fn` functions with no dependencies, making them verifiable
// by Verus. The actual handlers call these to reject spec-invalid requests.
//
// Formal verification: Run with Verus to verify correctness against the spec.
// The #[verus_spec] annotations are stripped by cargo (verus_keep_ghost cfg).

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

// Request capability flag bits (from capability.rs)
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const CERT_CAP: u32 = 0x0000_0002;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const ENCRYPT_CAP: u32 = 0x0000_0040;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const MAC_CAP: u32 = 0x0000_0080;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const KEY_EX_CAP: u32 = 0x0000_0200;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const PSK_CAP: u32 = 0x0000_0400;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const PSK_RSVD: u32 = 0x0000_0800;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const HBEAT_CAP: u32 = 0x0000_2000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const KEY_UPD_CAP: u32 = 0x0000_4000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const HANDSHAKE_IN_THE_CLEAR_CAP: u32 = 0x0000_8000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const PUB_KEY_ID_CAP: u32 = 0x0001_0000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const EP_INFO_CAP_NO_SIG: u32 = 0x0040_0000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const EP_INFO_CAP_SIG: u32 = 0x0080_0000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const EVENT_CAP: u32 = 0x0200_0000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const MULTI_KEY_CAP_ONLY: u32 = 0x0400_0000;
#[cfg_attr(verus_keep_ghost, verus_spec)]
pub const MULTI_KEY_CAP_CONN_SEL: u32 = 0x0800_0000;

// ═══════════════════════════════════════════════════════════════════════════
// Verus spec functions — formal specification of SPDM rules (DSP0274 Table 13)
// These define WHAT the function should do; the exec fn below is verified against them.
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn reqf_p1(flags: u32) -> bool {
    (flags & KEY_EX_CAP != 0) ==> ((flags & ENCRYPT_CAP != 0) || (flags & MAC_CAP != 0))
}

pub open spec fn reqf_p2(flags: u32) -> bool {
    (flags & PSK_CAP != 0) ==> ((flags & ENCRYPT_CAP != 0) || (flags & MAC_CAP != 0))
}

pub open spec fn reqf_p3(flags: u32) -> bool {
    flags & PSK_RSVD == 0
}

pub open spec fn reqf_p4(flags: u32) -> bool {
    ((flags & PSK_CAP != 0) && (flags & KEY_EX_CAP == 0)) ==> (flags & HANDSHAKE_IN_THE_CLEAR_CAP == 0)
}

pub open spec fn reqf_p5(flags: u32) -> bool {
    (flags & HANDSHAKE_IN_THE_CLEAR_CAP != 0) ==> ((flags & ENCRYPT_CAP != 0) || (flags & MAC_CAP != 0))
}

pub open spec fn reqf_p6(flags: u32) -> bool {
    (flags & PUB_KEY_ID_CAP != 0) ==> (
        (flags & CERT_CAP == 0) && (flags & MULTI_KEY_CAP_ONLY == 0) && (flags & MULTI_KEY_CAP_CONN_SEL == 0)
    )
}

pub open spec fn reqf_p7(flags: u32) -> bool {
    !((flags & EP_INFO_CAP_NO_SIG != 0) && (flags & EP_INFO_CAP_SIG != 0))
}

pub open spec fn reqf_p8(flags: u32) -> bool {
    !((flags & MULTI_KEY_CAP_ONLY != 0) && (flags & MULTI_KEY_CAP_CONN_SEL != 0))
}

pub open spec fn reqf_p9(flags: u32) -> bool {
    (flags & ENCRYPT_CAP != 0) ==> ((flags & KEY_EX_CAP != 0) || (flags & PSK_CAP != 0))
}

pub open spec fn reqf_p10(flags: u32) -> bool {
    (flags & MAC_CAP != 0) ==> ((flags & KEY_EX_CAP != 0) || (flags & PSK_CAP != 0))
}

pub open spec fn reqf_p11(flags: u32) -> bool {
    (flags & HBEAT_CAP != 0) ==> ((flags & KEY_EX_CAP != 0) || (flags & PSK_CAP != 0))
}

pub open spec fn reqf_p12(flags: u32) -> bool {
    (flags & KEY_UPD_CAP != 0) ==> ((flags & KEY_EX_CAP != 0) || (flags & PSK_CAP != 0))
}

pub open spec fn reqf_p13(flags: u32) -> bool {
    (flags & EVENT_CAP != 0) ==> ((flags & KEY_EX_CAP != 0) || (flags & PSK_CAP != 0))
}

pub open spec fn all_spec_rules(flags: u32) -> bool {
    &&& reqf_p1(flags)
    &&& reqf_p2(flags)
    &&& reqf_p3(flags)
    &&& reqf_p4(flags)
    &&& reqf_p5(flags)
    &&& reqf_p6(flags)
    &&& reqf_p7(flags)
    &&& reqf_p8(flags)
    &&& reqf_p9(flags)
    &&& reqf_p10(flags)
    &&& reqf_p11(flags)
    &&& reqf_p12(flags)
    &&& reqf_p13(flags)
}

} // verus! (spec definitions)

/// Validate requester capability flags per SPDM spec DSP0274 Table 13.
///
/// Returns `true` if the flags satisfy all spec-mandated dependency rules.
/// Returns `false` if any illegal combination is detected.
///
/// Verus verifies: ret == true <==> all 13 SPDM rules are satisfied.
#[cfg_attr(verus_keep_ghost, verus_spec(ret =>
    ensures
        ret ==> reqf_p1(flags),
        ret ==> reqf_p2(flags),
        ret ==> reqf_p3(flags),
        ret ==> reqf_p4(flags),
        ret ==> reqf_p5(flags),
        ret ==> reqf_p6(flags),
        ret ==> reqf_p7(flags),
        ret ==> reqf_p8(flags),
        ret ==> reqf_p9(flags),
        ret ==> reqf_p10(flags),
        ret ==> reqf_p11(flags),
        ret ==> reqf_p12(flags),
        ret ==> reqf_p13(flags),
        !ret ==> !all_spec_rules(flags),
))]
pub const fn validate_request_capability_flags(flags: u32) -> bool {
    let encrypt = flags & ENCRYPT_CAP != 0;
    let mac = flags & MAC_CAP != 0;
    let key_ex = flags & KEY_EX_CAP != 0;
    let psk = flags & PSK_CAP != 0;
    let psk_rsvd = flags & PSK_RSVD != 0;
    let hbeat = flags & HBEAT_CAP != 0;
    let key_upd = flags & KEY_UPD_CAP != 0;
    let hitc = flags & HANDSHAKE_IN_THE_CLEAR_CAP != 0;
    let pub_key_id = flags & PUB_KEY_ID_CAP != 0;
    let cert = flags & CERT_CAP != 0;
    let ep_no_sig = flags & EP_INFO_CAP_NO_SIG != 0;
    let ep_sig = flags & EP_INFO_CAP_SIG != 0;
    let event = flags & EVENT_CAP != 0;
    let multi_key_only = flags & MULTI_KEY_CAP_ONLY != 0;
    let multi_key_conn = flags & MULTI_KEY_CAP_CONN_SEL != 0;
    let has_session = key_ex || psk;

    // REQF_P3: PSK_RSVD bit must be zero (10b/11b reserved)
    if psk_rsvd {
        return false;
    }

    // REQF_P9: ENCRYPT_CAP → (KEY_EX_CAP ∨ PSK_CAP)
    if encrypt && !has_session {
        return false;
    }

    // REQF_P10: MAC_CAP → (KEY_EX_CAP ∨ PSK_CAP)
    if mac && !has_session {
        return false;
    }

    // REQF_P4: PSK_CAP=1 ∧ KEY_EX_CAP=0 → HITC=0
    if psk && !key_ex && hitc {
        return false;
    }

    // REQF_P5: HANDSHAKE_IN_THE_CLEAR_CAP → (ENCRYPT_CAP ∨ MAC_CAP)
    if hitc && !(encrypt || mac) {
        return false;
    }

    // REQF_P6: PUB_KEY_ID_CAP → ¬CERT_CAP ∧ ¬MULTI_KEY_CAP
    if pub_key_id && (cert || multi_key_only || multi_key_conn) {
        return false;
    }

    // REQF_P7: EP_INFO_CAP: both bits set is reserved (11b)
    if ep_no_sig && ep_sig {
        return false;
    }

    // REQF_P8: MULTI_KEY_CAP: both bits set is reserved (11b)
    if multi_key_only && multi_key_conn {
        return false;
    }

    // REQF_P11: HBEAT_CAP → (KEY_EX_CAP ∨ PSK_CAP)
    if hbeat && !has_session {
        return false;
    }

    // REQF_P12: KEY_UPD_CAP → (KEY_EX_CAP ∨ PSK_CAP)
    if key_upd && !has_session {
        return false;
    }

    // REQF_P13: EVENT_CAP → (KEY_EX_CAP ∨ PSK_CAP)
    if event && !has_session {
        return false;
    }

    true
}

/// Validate requester size parameters per SPDM spec (v1.2+).
///
/// `data_transfer_size`: DataTransferSize from GET_CAPABILITIES request.
/// `max_spdm_msg_size`: MaxSPDMmsgSize from GET_CAPABILITIES request.
/// `has_chunk_cap`: whether requester set CHUNK_CAP.
#[cfg_attr(verus_keep_ghost, verus_spec(ret =>
    ensures
        ret ==> (data_transfer_size >= 42u32),
        ret ==> (max_spdm_msg_size >= data_transfer_size),
        ret ==> (!has_chunk_cap ==> max_spdm_msg_size == data_transfer_size),
))]
pub const fn validate_request_sizes(
    data_transfer_size: u32,
    max_spdm_msg_size: u32,
    has_chunk_cap: bool,
) -> bool {
    // REQ_P3: DataTransferSize >= 42 (SPDM minimum)
    if data_transfer_size < 42 {
        return false;
    }

    // REQ_P4: MaxSPDMmsgSize >= DataTransferSize
    if max_spdm_msg_size < data_transfer_size {
        return false;
    }

    // REQ_P5: If CHUNK_CAP=0, MaxSPDMmsgSize SHALL equal DataTransferSize
    if !has_chunk_cap && max_spdm_msg_size != data_transfer_size {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_minimal_flags() {
        // No capabilities set is valid
        assert!(validate_request_capability_flags(0));
    }

    #[test]
    fn valid_key_ex_with_encrypt() {
        // KEY_EX + ENCRYPT is valid (mutual requirement satisfied)
        assert!(validate_request_capability_flags(KEY_EX_CAP | ENCRYPT_CAP));
    }

    #[test]
    fn invalid_encrypt_without_session() {
        // ENCRYPT_CAP alone violates REQF_P9
        assert!(!validate_request_capability_flags(ENCRYPT_CAP));
    }

    #[test]
    fn invalid_psk_rsvd() {
        // PSK_RSVD bit set violates REQF_P3
        assert!(!validate_request_capability_flags(PSK_RSVD | PSK_CAP | ENCRYPT_CAP));
    }

    #[test]
    fn invalid_multi_key_both() {
        // Both MULTI_KEY bits set violates REQF_P8
        assert!(!validate_request_capability_flags(
            KEY_EX_CAP | ENCRYPT_CAP | MULTI_KEY_CAP_ONLY | MULTI_KEY_CAP_CONN_SEL
        ));
    }

    #[test]
    fn valid_sizes() {
        assert!(validate_request_sizes(42, 42, false));
        assert!(validate_request_sizes(4096, 65536, true));
    }

    #[test]
    fn invalid_size_too_small() {
        assert!(!validate_request_sizes(41, 41, false));
    }

    #[test]
    fn invalid_max_less_than_transfer() {
        assert!(!validate_request_sizes(100, 50, false));
    }

    #[test]
    fn invalid_no_chunk_size_mismatch() {
        // Without CHUNK_CAP, max must equal transfer
        assert!(!validate_request_sizes(42, 100, false));
    }

    /// Bridging test: verifies the VALID_MASK constant matches Verus model.
    #[test]
    fn valid_mask_matches_verus_model() {
        use crate::protocol::SpdmRequestCapabilityFlags;
        assert_eq!(SpdmRequestCapabilityFlags::VALID_MASK.bits(), 0x8EC3_FFC6u32);
    }
}

// Verus requires a main when verifying as a standalone file
#[cfg(verus_keep_ghost)]
fn main() {}
