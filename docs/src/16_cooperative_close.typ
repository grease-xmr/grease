== Co-operative Close <coopClose>

Either party can initiate a co-operative close of the channel at any time by sending their latest adapter offset to the counterparty in a
`RequestChannelClose` message. As an illustration, we will assume that the customer initiates the close.

When the merchant receives the offset, it verifies it, by trying to complete the closing transaction signature for the expected update
count. It then broadcasts the transaction to the network. The channel is then marked as `Closed`. If the closure was successful, the
merchant responds with an `ChannelCloseSuccess` message. If any errors occur, the merchant responds with a `RequestCloseFailed` message, and
the channel remains `Open`. If the merchant did not provide the transaction id in its response, the customer may use the provided offset to
reconstruct and broadcast the closing transaction herself.

If a party becomes unresponsive during the co-operative close process, one may initiate a force-close via the KES, as described in
@kesDesign.


=== Channel Close messages <closeMessages>

A party sends a `RequestChannelClose` message to initiate a co-operative channel closure.

```rs
pub struct RequestChannelClose {
  /// The globally unique channel id
  channel_id: ChannelId,
  /// The latest adapter offset for the initiating party
  offset: Scalar,
  /// The update count corresponding to the latest adapter offset
  update_count: u64,
}
```

The counterparty responds with either a `RequestCloseFailed` or `ChannelCloseSuccess` message.

```rs
pub struct ChannelCloseSuccess {
  /// The globally unique channel id
  channel_id: ChannelId,
  /// The latest adapter offset for the responding party
  offset: Scalar,
  /// The transaction id of the closing transaction. Optional.
  txid: Option<TxId>,
}
```

```rs
pub struct RequestCloseFailed {
  /// The globally unique channel id
  channel_id: ChannelId,
  /// An error code indicating the reason for the failure
  reason: CloseFailureReason,
}
```

#figure(include "../diagrams/close_channel_sequence.md", caption: [The Channel Close sequence]) <close_channel_sequence>
