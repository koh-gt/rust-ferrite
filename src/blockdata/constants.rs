// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Blockdata constants.
//!
//! This module provides various constants relating to the blockchain and
//! consensus code. In particular, it defines the genesis block and its
//! single transaction.
//!

use prelude::*;

use hashes::hex::{HexIterator, Error as HexError};
use hashes::sha256d;
use blockdata::opcodes;
use blockdata::script;
use blockdata::transaction::{OutPoint, Transaction, TxOut, TxIn};
use blockdata::block::{Block, BlockHeader};
use blockdata::witness::Witness;
use network::constants::Network;
use util::uint::Uint256;

/// The maximum allowable sequence number
pub const MAX_SEQUENCE: u32 = 0xFFFFFFFF;
/// How many satoshis are in "one bitcoin"
pub const COIN_VALUE: u64 = 100_000_000;
/// How many seconds between blocks we expect on average
pub const TARGET_BLOCK_SPACING: u32 = 60;
/// How many blocks between diffchanges
pub const DIFFCHANGE_INTERVAL: u32 = 10;
/// How much time on average should occur between diffchanges
pub const DIFFCHANGE_TIMESPAN: u32 = 60 * 10;
/// The maximum allowed weight for a block, see BIP 141 (network rule)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// The minimum transaction weight for a valid serialized transaction
pub const MIN_TRANSACTION_WEIGHT: u32 = 4 * 60;
/// The factor that non-witness serialization data is multiplied by during weight calculation
pub const WITNESS_SCALE_FACTOR: usize = 4;
/// The maximum allowed number of signature check operations in a block
pub const MAX_BLOCK_SIGOPS_COST: i64 = 80_000;
/// Mainnet (bitcoin) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 36; // 0x24
/// Mainnet (bitcoin) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 35; // 0x23
/// Test (testnet, signet, regtest) pubkey address prefix.
pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111;
/// Test (testnet, signet, regtest) script address prefix.
pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 35;
/// The maximum allowed script size.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// How may blocks between halvings.
pub const SUBSIDY_HALVING_INTERVAL: u32 = 301_107;

/// In Bitcoind this is insanely described as ~((u256)0 >> 32)
pub fn max_target(_: Network) -> Uint256 {
    Uint256::from_u64(0xFFFF).unwrap() << 208
}

/// The maximum value allowed in an output (useful for sanity checking,
/// since keeping everything below this value should prevent overflows
/// if you are doing anything remotely sane with monetary values).
pub fn max_money(_: Network) -> u64 {
    60_221_400 * COIN_VALUE
}

/// Constructs and returns the coinbase (and only) transaction of the Bitcoin genesis block
fn bitcoin_genesis_tx() -> Transaction {
    // Base
    let mut ret = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![],
        output: vec![],
        mw_tx: None,
        is_hog_ex: false
    };

    // Inputs
    let in_script = script::Builder::new().push_scriptint(486604799)
                                          .push_scriptint(4)
                                          .push_slice("ST 22Nov22 Singapore was second biggest user of FTX pre collapse".as_bytes())
                                          .into_script();
    ret.input.push(TxIn {
        previous_output: OutPoint::null(),
        script_sig: in_script,
        sequence: MAX_SEQUENCE,
        witness: Witness::default(),
    });

    // Outputs
    let script_bytes: Result<Vec<u8>, HexError> =
        HexIterator::new("04a7cb90400675f171c818b53ea84938118e5f1c668a36ac4ca4cb2e502ae12cdadd5ab524eb2319d5e68f5433229e8d1dd0bf60e62f6d1ba09a05d48562d757a3").unwrap()
            .collect();
    let out_script = script::Builder::new()
        .push_slice(script_bytes.unwrap().as_slice())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    ret.output.push(TxOut {
        value: 100 * COIN_VALUE,
        script_pubkey: out_script
    });

    // end
    ret
}

/// Constructs and returns the genesis block
pub fn genesis_block(network: Network) -> Block {
    let txdata = vec![bitcoin_genesis_tx()];
    let hash: sha256d::Hash = txdata[0].txid().into();
    let merkle_root = hash.into();
    match network {
        Network::Bitcoin => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1669136135,
                    bits: 0x1e0ffff0,
                    nonce: 1766816
                },
                txdata,
                mweb_block: None
            }
        }
        Network::Testnet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1669136958,
                    bits: 0x1e0ffff0,
                    nonce: 336866
                },
                txdata,
                mweb_block: None
            }
        }
        Network::Signet => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1598918400,
                    bits: 0x1e0377ae,
                    nonce: 52613770
                },
                txdata,
                mweb_block: None
            }
        }
        Network::Regtest => {
            Block {
                header: BlockHeader {
                    version: 1,
                    prev_blockhash: Default::default(),
                    merkle_root,
                    time: 1296688602,
                    bits: 0x207fffff,
                    nonce: 2
                },
                txdata,
                mweb_block: None
            }
        }
    }
}

#[cfg(test)]
mod test {
    use hashes::hex::FromHex;

    use network::constants::Network;
    use consensus::encode::serialize;
    use blockdata::constants::{genesis_block, bitcoin_genesis_tx};
    use blockdata::constants::{MAX_SEQUENCE, COIN_VALUE};

    #[test]
    fn bitcoin_genesis_first_transaction() {
        let gen = bitcoin_genesis_tx();

        // assert_eq!(gen.version, 1);
        // assert_eq!(gen.input.len(), 1);
        // assert_eq!(gen.input[0].previous_output.txid, Default::default());
        // assert_eq!(gen.input[0].previous_output.vout, 0xFFFFFFFF);
        // assert_eq!(serialize(&gen.input[0].script_sig),
        //            Vec::from_hex("4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536").unwrap());

        // assert_eq!(gen.input[0].sequence, MAX_SEQUENCE);
        // assert_eq!(gen.output.len(), 1);
        // assert_eq!(serialize(&gen.output[0].script_pubkey),
        //            Vec::from_hex("4341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac").unwrap());
        // assert_eq!(gen.output[0].value, 100 * COIN_VALUE);
        // assert_eq!(gen.lock_time, 0);

        assert_eq!(format!("{:x}", gen.wtxid()),
                   "3db2b5aa928b56b8f38dc404f5bdb9e76209906b91ba175361acdc2405b19592".to_string());
    }

    #[test]
    fn bitcoin_genesis_full_block() {
        let gen = genesis_block(Network::Bitcoin);

        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                   "3db2b5aa928b56b8f38dc404f5bdb9e76209906b91ba175361acdc2405b19592".to_string());
        assert_eq!(gen.header.time, 1317972665);
        assert_eq!(gen.header.bits, 0x1e0ffff0);
        assert_eq!(gen.header.nonce, 2084524493);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "46ca17415c18e43f5292034ebf9bbd10de80a61fc6dc17180e6609f33d3b48f3".to_string());
    }

    #[test]
    fn testnet_genesis_full_block() {
        let gen = genesis_block(Network::Testnet);
        assert_eq!(gen.header.version, 1);
        assert_eq!(gen.header.prev_blockhash, Default::default());
        assert_eq!(format!("{:x}", gen.header.merkle_root),
                  "3db2b5aa928b56b8f38dc404f5bdb9e76209906b91ba175361acdc2405b19592".to_string());
        assert_eq!(gen.header.time, 1486949366);
        assert_eq!(gen.header.bits, 0x1e0ffff0);
        assert_eq!(gen.header.nonce, 293345);
        assert_eq!(format!("{:x}", gen.header.block_hash()),
                   "7a9f43d6e86eefa66e2b79918b2235c9362106f3d9f11f37f7a33450ceae73c1".to_string());
    }

    #[test]
    fn signet_genesis_full_block() {
        // Litecoin: disabled test as LTC has no signet
        // let gen = genesis_block(Network::Signet);
        // assert_eq!(gen.header.version, 1);
        // assert_eq!(gen.header.prev_blockhash, Default::default());
        // assert_eq!(format!("{:x}", gen.header.merkle_root),
        //           "97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9".to_string());
        // assert_eq!(gen.header.time, 1598918400);
        // assert_eq!(gen.header.bits, 0x1e0377ae);
        // assert_eq!(gen.header.nonce, 52613770);
        // assert_eq!(format!("{:x}", gen.header.block_hash()),
        //            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6".to_string());
    }
}

