use crate::state_machine::lifecycle::LifecycleStage;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeoutReason {
    /// The reason for the timeout
    reason: String,
    /// The phase of the lifecycle when the timeout occurred
    stage: LifecycleStage,
}

impl TimeoutReason {
    pub fn new(reason: impl Into<String>, stage: LifecycleStage) -> Self {
        TimeoutReason { reason: reason.into(), stage }
    }

    /// Get the reason for the timeout
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Get the stage of the lifecycle when the timeout occurred
    pub fn stage(&self) -> LifecycleStage {
        self.stage
    }
}
