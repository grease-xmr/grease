use crate::amount::MoneroAmount;
use crate::crypto::zk_objects::{KesProof, Proofs0, PublicProof0, ShardInfo, UpdateInfo, UpdateProofs};
use crate::monero::data_objects::{MultisigWalletData, TransactionId};
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
    MyProof0Generated(Box<Proofs0>),
    PeerProof0Received(Box<PublicProof0>),
    KesShards(Box<ShardInfo>),
    KesCreated(Box<KesProof>),
    FundingTxConfirmed(Box<(TransactionId, MoneroAmount)>),
    FinalTxConfirmed(Box<TransactionId>),
    ChannelUpdate(Box<(UpdateProofs, UpdateInfo)>),
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
            LifeCycleEvent::KesCreated(_) => write!(f, "KesCreated"),
            LifeCycleEvent::FundingTxConfirmed(_) => write!(f, "FundingTxConfirmed"),
            LifeCycleEvent::MyProof0Generated(_) => write!(f, "MyProof0Generated"),
            LifeCycleEvent::PeerProof0Received(_) => write!(f, "PeerProof0Received"),
            LifeCycleEvent::ChannelUpdate(u) => write!(f, "ChannelUpdate_{}", u.1.index),
            LifeCycleEvent::OnStartClose => write!(f, "OnStartClose"),
            LifeCycleEvent::RejectNewChannel(_) => write!(f, "OnRejectNewChannel"),
            LifeCycleEvent::OnForceClose => write!(f, "OnForceClose"),
            LifeCycleEvent::OnDisputeResolved => write!(f, "OnDisputeResolved"),
            LifeCycleEvent::FinalTxConfirmed(_) => write!(f, "FinalTransactionConfirmed"),
            LifeCycleEvent::KesShards(_) => write!(f, "MultiSigKesShards"),
        }
    }
}
