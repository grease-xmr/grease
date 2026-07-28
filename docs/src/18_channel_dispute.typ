== Dispute resolution

When cooperation breaks down — a peer becomes unresponsive, or one party tries to close the channel with an outdated state — the aggrieved
peer presents its latest cross-signed record to the arbiter. The arbiter opens an adjudication window, lets the counterparty answer with any
newer record, and at the window's close attests the statement for the highest update count it has seen. That attestation unseals exactly the
offset that closes the channel at the true latest state; a stale close is never attested, and so can never be completed.

The dispute process, the arbiter's state machine, and the guarantees it provides are described in full in @arbiterDesign, with the
presentation flow in @disputeFlow.
