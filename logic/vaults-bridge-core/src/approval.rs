// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Approval channel between the protocol engine and an out-of-band UI.

use std::sync::Arc;

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAction {
    /// Release a stored credential to the host.
    Release,
    /// Save a new credential.
    Save,
    /// Update an existing live credential (origin+username already exists).
    Update,
    /// Restore an archived credential and update its password.
    RestoreAndUpdate,
    /// Device generates a new strong random password and stores it.
    Generate,
    /// Device generates a new password to replace an existing live credential.
    GenerateAndUpdate,
    /// Device generates a new password and restores an archived credential.
    GenerateAndRestore,
    /// Bulk import from an exported password manager file. Carries the
    /// detected source label and entry count via the surrounding
    /// `ApprovalRequest` (origin = source label, username = "<count> entries").
    Import,
}

impl ApprovalAction {
    /// One-line title for the approval card. UI may further format.
    pub fn title(self) -> &'static str {
        match self {
            ApprovalAction::Release => "Release password?",
            ApprovalAction::Save => "Save password?",
            ApprovalAction::Update => "Update password?",
            ApprovalAction::RestoreAndUpdate => "Restore and update?",
            ApprovalAction::Generate => "Generate password?",
            ApprovalAction::GenerateAndUpdate => "Generate new password?",
            ApprovalAction::GenerateAndRestore => "Restore and generate?",
            ApprovalAction::Import => "Import passwords?",
        }
    }
}

#[derive(Clone)]
pub struct ApprovalRequest {
    pub action: ApprovalAction,
    pub origin: String,
    pub username: String,
    pub request_nonce: u64,
}

impl std::fmt::Debug for ApprovalRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalRequest")
            .field("action", &self.action)
            .field("origin", &self.origin)
            .field("username", &"<redacted>")
            .field("request_nonce", &self.request_nonce)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Reject,
    Timeout,
}

#[async_trait]
pub trait Approver: Send + Sync {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision;

    /// Cancel an in-flight approval request, if this approver has one.
    ///
    /// The protocol engine exposes `cancel` as a best-effort escape hatch
    /// for hosts that tear down a request while the device is showing an
    /// approval card. Stateless approvers can keep the default no-op.
    fn cancel_pending(&self) -> bool {
        false
    }
}

pub type ArcApprover = Arc<dyn Approver>;

/// Test/sim helper: always approve.
pub struct AutoApprove;

#[async_trait]
impl Approver for AutoApprove {
    async fn request(&self, _req: ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Approve
    }
}

/// Test/sim helper: always reject.
pub struct AutoReject;

#[async_trait]
impl Approver for AutoReject {
    async fn request(&self, _req: ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Reject
    }
}
