= Future extensions and known limitations

The Grease protocol represents the first attempt to extend the high-security features of Monero while also using the problem-solving
flexibility of the latest Turing-complete ZKP tools. Given the rate at which the ZKP technology is advancing there may be many more
opportunities to extend Monero's security to new features and markets, connecting the future of Monero with the larger blockchain community.

KES funding specifics are not assumed. If the KES runs on a ZKP-compatible smart contract blockchain then both peers will require a funded
temporary key pair for the blockchain. With account abstraction this would be trivial. Without account abstraction this can be implemented
by the peer that funds the KES to transfer gas to the anonymous peer to accommodate a possible dispute, with the anonymous peer refunding
the gas after channel closure (or simply revealing the temporary private key).
