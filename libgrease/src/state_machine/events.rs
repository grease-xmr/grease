use crate::amount::MoneroDelta;
use crate::monero::data_objects::{TransactionId, TransactionRecord};
use crate::state_machine::closing_channel::ChannelCloseRecord;
use crate::state_machine::open_channel::AppliedUpdate;
use crate::state_machine::proposing_channel::{NewChannelProposal, RejectProposalReason};
use crate::state_machine::timeouts::TimeoutReason;
use crate::wallet::multisig_wallet::MultisigWallet;
use crate::Ed25519;
use ciphersuite::Ciphersuite;
use std::fmt::{Display, Formatter};

pub enum LifeCycleEvent<KC: Ciphersuite = Ed25519> {
    /// Customer received acceptance from merchant - triggers transition to Establishing
    ProposalAcceptedByMerchant(Box<NewChannelProposal<KC>>),
    /// Merchant accepted customer's proposal - triggers transition to Establishing
    MerchantAcceptedProposal(Box<NewChannelProposal<KC>>),
    /// Proposal rejected by peer
    RejectProposal(Box<RejectProposalReason>),
    Timeout(Box<TimeoutReason>),
    MultiSigWalletCreated(Box<MultisigWallet>),
    FundingTxWatcher(Vec<u8>),
    FundingTxConfirmed(Box<TransactionRecord>),
    FinalTxConfirmed(Box<TransactionId>),
    ChannelUpdate(Box<(MoneroDelta, AppliedUpdate)>),
    CloseChannel(Box<ChannelCloseRecord>),
    OnForceClose,
    OnDisputeResolved,
}

impl<KC: Ciphersuite> Display for LifeCycleEvent<KC> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LifeCycleEvent::ProposalAcceptedByMerchant(_) => write!(f, "ProposalAcceptedByMerchant"),
            LifeCycleEvent::MerchantAcceptedProposal(_) => write!(f, "MerchantAcceptedProposal"),
            LifeCycleEvent::Timeout(_) => write!(f, "OnTimeout"),
            LifeCycleEvent::MultiSigWalletCreated(_) => write!(f, "OnMultiSigWalletCreated"),
            LifeCycleEvent::FundingTxWatcher(_) => write!(f, "SaveFundingTxWatcher"),
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
