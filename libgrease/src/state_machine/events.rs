use crate::amount::MoneroDelta;
use crate::cryptography::pok::KesPoKProofs;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::multisig::MultisigWalletData;
use crate::state_machine::closing_channel::ChannelCloseRecord;
use crate::state_machine::open_channel::UpdateRecord;
use crate::state_machine::proposing_channel::{NewChannelProposal, RejectProposalReason};
use crate::state_machine::timeouts::TimeoutReason;
use ciphersuite::{Ciphersuite, Ed25519};
use std::fmt::{Display, Formatter};

pub enum LifeCycleEvent<SF: Ciphersuite = grease_grumpkin::Grumpkin, KC: Ciphersuite = Ed25519> {
    /// Customer received acceptance from merchant - triggers transition to Establishing
    ProposalAcceptedByMerchant(Box<NewChannelProposal<KC>>),
    /// Merchant accepted customer's proposal - triggers transition to Establishing
    MerchantAcceptedProposal(Box<NewChannelProposal<KC>>),
    /// Proposal rejected by peer
    RejectProposal(Box<RejectProposalReason>),
    Timeout(Box<TimeoutReason>),
    MultiSigWalletCreated(Box<MultisigWalletData>),
    FundingTxWatcher(Vec<u8>),
    /// The KES client has been initialized with cryptographic secrets for this channel.
    KesClientInitialized,
    KesCreated(Box<KesPoKProofs<KC>>),
    FundingTxConfirmed(Box<TransactionRecord>),
    FinalTxConfirmed(Box<TransactionId>),
    ChannelUpdate(Box<(MoneroDelta, UpdateRecord<SF>)>),
    CloseChannel(Box<ChannelCloseRecord<SF>>),
    OnForceClose,
    OnDisputeResolved,
}

impl<SF: Ciphersuite, KC: Ciphersuite> Display for LifeCycleEvent<SF, KC> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LifeCycleEvent::ProposalAcceptedByMerchant(_) => write!(f, "ProposalAcceptedByMerchant"),
            LifeCycleEvent::MerchantAcceptedProposal(_) => write!(f, "MerchantAcceptedProposal"),
            LifeCycleEvent::Timeout(_) => write!(f, "OnTimeout"),
            LifeCycleEvent::MultiSigWalletCreated(_) => write!(f, "OnMultiSigWalletCreated"),
            LifeCycleEvent::FundingTxWatcher(_) => write!(f, "SaveFundingTxWatcher"),
            LifeCycleEvent::KesClientInitialized => write!(f, "KesClientInitialized"),
            LifeCycleEvent::KesCreated(_) => write!(f, "KesCreated"),
            LifeCycleEvent::FundingTxConfirmed(_) => write!(f, "FundingTxConfirmed"),
            LifeCycleEvent::ChannelUpdate(_) => write!(f, "ChannelUpdate"),
            LifeCycleEvent::CloseChannel(_) => write!(f, "CloseChannel"),
            LifeCycleEvent::RejectProposal(_) => write!(f, "RejectProposal"),
            LifeCycleEvent::OnForceClose => write!(f, "OnForceClose"),
            LifeCycleEvent::OnDisputeResolved => write!(f, "OnDisputeResolved"),
            LifeCycleEvent::FinalTxConfirmed(_) => write!(f, "FinalTransactionConfirmed"),
        }
    }
}
