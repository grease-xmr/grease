use crate::amount::MoneroAmount;
use crate::kes::{FundingTransaction, KesInitializationResult, ShardInfo};
use crate::monero::data_objects::{ChannelUpdate, MultisigSplitSecrets, MultisigWalletData, TransactionId};
use crate::state_machine::commitment_tx::CommitmentTransaction;
use crate::state_machine::new_channel::RejectNewChannelReason;
use crate::state_machine::timeouts::TimeoutReason;
use crate::state_machine::ProposedChannelInfo;
use std::fmt::{Display, Formatter};

pub enum LifeCycleEvent {
    /// The channel proposal has been verified and accepted by both parties.
    VerifiedProposal(Box<ProposedChannelInfo>),
    RejectNewChannel(Box<RejectNewChannelReason>),
    Timeout(Box<TimeoutReason>),
    MultiSigWalletCreated(Box<MultisigWalletData>),
    FundingTxWatcher(Vec<u8>),
    CommitmentTxCreated(Box<CommitmentTransaction>),
    CommitmentZeroProof(Vec<u8>),
    KesShards(Box<ShardInfo>),
    KesCreated(Box<KesInitializationResult>),
    FundingTxConfirmed(Box<(TransactionId, MoneroAmount)>),
    OnUpdateChannel(Box<ChannelUpdate>),
    FinalTxConfirmed(Box<TransactionId>),
    OnStartClose,
    OnForceClose,
    OnDisputeResolved,
}

impl Display for LifeCycleEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LifeCycleEvent::VerifiedProposal(_) => write!(f, "VerifiedProposal"),
            LifeCycleEvent::Timeout(_) => write!(f, "OnTimeout"),
            LifeCycleEvent::MultiSigWalletCreated(_) => write!(f, "OnMultiSigWalletCreated"),
            LifeCycleEvent::FundingTxWatcher(_) => write!(f, "SaveFundingTxWatcher"),
            LifeCycleEvent::CommitmentTxCreated(_) => write!(f, "CommitmentTxCreated"),
            LifeCycleEvent::CommitmentZeroProof(_) => write!(f, "Commitment0Proof"),
            LifeCycleEvent::KesCreated(_) => write!(f, "KesCreated"),
            LifeCycleEvent::FundingTxConfirmed(_) => write!(f, "FundingTxConfirmed"),
            LifeCycleEvent::OnUpdateChannel(_) => write!(f, "OnUpdateChannel"),
            LifeCycleEvent::OnStartClose => write!(f, "OnStartClose"),
            LifeCycleEvent::RejectNewChannel(_) => write!(f, "OnRejectNewChannel"),
            LifeCycleEvent::OnForceClose => write!(f, "OnForceClose"),
            LifeCycleEvent::OnDisputeResolved => write!(f, "OnDisputeResolved"),
            LifeCycleEvent::FinalTxConfirmed(_) => write!(f, "FinalTransactionConfirmed"),
            LifeCycleEvent::KesShards(_) => write!(f, "MultiSigKesShards"),
        }
    }
}
