// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Kani formal verification proofs for SPDM GET_CAPABILITIES/CAPABILITIES
//! message handling (requester and responder).
//!
//! These proofs verify that the spdm-rs implementation meets the SPDM
//! specification (DSP0274) requirements for capability flag validation.

#[cfg(kani)]
pub mod capability_proofs;
