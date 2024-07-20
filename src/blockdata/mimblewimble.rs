// MimbleWimble transaction
#![allow(missing_docs)]
use crate::prelude::*;
use crate::io;

use consensus::{encode, Decodable, Encodable};
use secp256k1::PublicKey;
use Script;
use VarInt;

pub enum KernelFeatures {
    FeeFeatureBit = 0x01,
    PeginFeatureBit = 0x02,
    PegoutFeatureBit = 0x04,
    HeightLockFeatureBit = 0x08,
    StealthExcessFeatureBit = 0x10,
    ExtraDataFeatureBit = 0x20
}

pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMessageStandardFields {
    pub key_exchange_pubkey: PublicKey,
    pub view_tag: u8,
    pub masked_value: u64,
    pub masked_nonce: [u8; 16]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OutputMessage {
    pub features: u8,
    pub standard_fields: Option<OutputMessageStandardFields>,
    pub extra_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Output {
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub commitment: [u8; 33],
    pub sender_public_key: PublicKey,
    pub receiver_public_key: PublicKey,
    pub message: OutputMessage,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub range_proof: [u8; 675],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64],
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Input {
    pub features: u8,
    pub output_id: [u8; 32],
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub commitment: [u8; 33],
    pub input_public_key: Option<PublicKey>,
    pub output_public_key: PublicKey,
    pub extra_data: Vec<u8>,
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PegOutCoin {
    pub amount: i64,
    pub script_pub_key: Script
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Kernel {
    pub features: u8,
    pub fee: Option<i64>,
    pub pegin: Option<i64>,
    pub pegouts: Vec<PegOutCoin>,
    pub lock_height: Option<i32>,
    pub stealth_excess: Option<PublicKey>,
    pub extra_data: Vec<u8>,
    // Remainder of the sum of all transaction commitments. 
    // If the transaction is well formed, amounts components should sum to zero and the excess is hence a valid public key.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub excess: [u8; 33],
    // The signature proving the excess is a valid public key, which signs the transaction fee.
    #[cfg_attr(feature = "serde", serde(with = "serde_big_array::BigArray"))]
    pub signature: [u8; 64]
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxBody {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub kernels: Vec<Kernel>
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transaction {
    pub kernel_offset: [u8; 32],
    pub stealth_offset: [u8; 32],
    pub body: TxBody
}

fn read_amount<D: io::Read>(stream: &mut D) -> Result<i64, encode::Error> {
    let mut n: i64 = 0;
    loop {
        let ch_data = u8::consensus_decode(&mut *stream)?;
        let a = n << 7;
        let b = (ch_data & 0x7F) as i64;
        n = a | b;
        if (ch_data & 0x80) != 0 {
            n += 1;
        }
        else {
            break;
        }
    }
    Ok(n)
}

fn write_amount<W: io::Write>(amount: i64, mut writer: W) -> Result<usize, io::Error> {
    let mut n = amount;
    const SIZE: usize = 10;
    let mut tmp = [0u8; SIZE];
    let mut len = 0;
    loop {
        let a = (n & 0x7F) as u8;
        let b = (if len != 0 { 0x80 } else { 0x00 }) as u8;
        tmp[len] = a | b;
        if n <= 0x7F {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    };
    for _ in 0 .. len {
        let _ = u8::consensus_encode(&tmp[len], &mut writer);
    };
    Ok(len)
}

fn read_array_len<D: io::Read>(mut stream: D) -> u64 {
    return VarInt::consensus_decode(&mut stream).expect("read error").0;
}

impl Decodable for PegOutCoin {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let amount = read_amount(&mut d)?;
        let script_pub_key = Script::consensus_decode(&mut d)?;
        Ok(PegOutCoin { amount, script_pub_key })
    }
}

impl Encodable for PegOutCoin {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += write_amount(self.amount, &mut writer)?;
        len += &self.script_pub_key.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for Kernel {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d).expect("read error");
        let fee =
            if features & (KernelFeatures::FeeFeatureBit as u8) != 0 {
                Some(read_amount(&mut d)?)
            }
            else {
                None
            };
        let pegin =
            if features & (KernelFeatures::PeginFeatureBit as u8) != 0 {
                Some(read_amount(&mut d)?)
            }
            else {
                None
            };
        let mut pegouts = Vec::<PegOutCoin>::new();
        if features & (KernelFeatures::PegoutFeatureBit as u8) != 0 {
            let len = read_array_len(&mut d);
            for _ in 0 .. len {
                pegouts.push(PegOutCoin::consensus_decode(&mut d)?);
            }
        }
        let lock_height =
            if features & (KernelFeatures::HeightLockFeatureBit as u8) != 0 {
                Some(i32::consensus_decode(&mut d)?)
            }
            else {
                None
            };
        let stealth_excess =
            if features & (KernelFeatures::StealthExcessFeatureBit as u8) != 0 {
                let pubkey_bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
                Some(PublicKey::from_slice(&pubkey_bytes).unwrap())
            }
            else {
                None
            };
        let mut extra_data = Vec::<u8>::new();
        if features & (KernelFeatures::ExtraDataFeatureBit as u8) != 0 {
            extra_data = Vec::<u8>::consensus_decode(&mut d)?;
        }
        let excess: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let signature: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        Ok(
            Kernel { 
                features, 
                fee, 
                pegin, 
                pegouts, 
                lock_height, 
                stealth_excess, 
                extra_data,
                excess,
                signature
            }
        )
    }
}

impl Encodable for Kernel {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(&mut writer)?;
        if self.features & (KernelFeatures::FeeFeatureBit as u8) != 0 {
            len += write_amount(self.fee.unwrap(), &mut writer)?;
        }
        if self.features & (KernelFeatures::PeginFeatureBit as u8) != 0 {
            len += self.pegin.unwrap().consensus_encode(&mut writer)?;
        }
        if self.features & (KernelFeatures::PegoutFeatureBit as u8) != 0 {
            len += VarInt(self.pegouts.len() as u64).consensus_encode(&mut writer)?;
            for pegout in &self.pegouts {
                pegout.consensus_encode(&mut writer)?;
            }
        }
        if self.features & (KernelFeatures::HeightLockFeatureBit as u8) != 0 {
            len += self.lock_height.unwrap().consensus_encode(&mut writer)?;
        }
        if self.features & (KernelFeatures::StealthExcessFeatureBit as u8) != 0 {
            len += self.stealth_excess.unwrap().serialize().consensus_encode(&mut writer)?;
        }
        if self.features & (KernelFeatures::ExtraDataFeatureBit as u8) != 0 {
            len += self.extra_data.consensus_encode(&mut writer)?;
        }
        len += self.excess.consensus_encode(&mut writer)?;
        len += self.signature.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for Vec<Kernel> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Kernel> {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut writer)?;
        for kernel in self {
            len += kernel.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Vec<Input> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Input> {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut writer)?;
        for input in self {
            len += input.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Input {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let output_id: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let commitment: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let output_public_key_bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let output_public_key = PublicKey::from_slice(&output_public_key_bytes).unwrap();
        let input_public_key =
            if features & 1 != 0 {
                let input_public_key_bytes: [u8; 33] = Decodable::consensus_decode(&mut d)?;
                Some(PublicKey::from_slice(&input_public_key_bytes).unwrap())
            }
            else {
                None
            };
        let mut extra_data = Vec::<u8>::new();
        if features & 2 != 0 {
            // extra data
            extra_data = Vec::<u8>::consensus_decode(&mut d)?;
        }
        let signature: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        return Ok(
            Input { 
                features, 
                output_id, 
                commitment, 
                input_public_key, 
                output_public_key, 
                extra_data,
                signature
            }
        );
    }
}

impl Encodable for Input {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(&mut writer)?;
        len += self.output_id.consensus_encode(&mut writer)?;
        len += self.commitment.consensus_encode(&mut writer)?;
        len += self.output_public_key.serialize().consensus_encode(&mut writer)?;
        if self.features & 1 != 0 {
            len += self.input_public_key.unwrap().serialize().consensus_encode(&mut writer)?;
        }
        if self.features & 2 != 0 {
            len += self.extra_data.consensus_encode(&mut writer)?;
        }
        len += self.signature.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for Vec<Output> {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let len = VarInt::consensus_decode(&mut d)?.0;
        let mut ret = Vec::with_capacity(len as usize);
        for _ in 0..len {
            ret.push(Decodable::consensus_decode(&mut d)?);
        }
        Ok(ret)
    }
}

impl Encodable for Vec<Output> {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += VarInt(self.len() as u64).consensus_encode(&mut writer)?;
        for output in self {
            len += output.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let kernel_offset: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let stealth_offset: [u8; 32] = Decodable::consensus_decode(&mut d)?;
        let body= TxBody::consensus_decode(d)?;
        return Ok(Transaction{ kernel_offset, stealth_offset, body });
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.kernel_offset.consensus_encode(&mut writer)?;
        len += self.stealth_offset.consensus_encode(&mut writer)?;
        len += self.body.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Decodable for TxBody {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let inputs = Vec::<Input>::consensus_decode(&mut d)?;
        let outputs = Vec::<Output>::consensus_decode(&mut d)?;
        let kernels = Vec::<Kernel>::consensus_decode(&mut d)?;
        return Ok(TxBody{ inputs, outputs, kernels });
    }
}

impl Encodable for TxBody {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.inputs.consensus_encode(&mut writer)?;
        len += self.outputs.consensus_encode(&mut writer)?;
        len += self.kernels.consensus_encode(&mut writer)?;
        Ok(len)
    }
}

impl Encodable for Output {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.commitment.consensus_encode(&mut writer)?;
        len += self.sender_public_key.serialize().consensus_encode(&mut writer)?;
        len += self.receiver_public_key.serialize().consensus_encode(&mut writer)?;
        len += self.message.consensus_encode(&mut writer)?;
        len += self.range_proof.consensus_encode(&mut writer)?;
        len += self.signature.consensus_encode(&mut writer)?;
        return Ok(len);
    }
}

impl Decodable for Output {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let commitment = Decodable::consensus_decode(&mut d)?;
        let sender_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let sender_public_key = PublicKey::from_slice(&sender_pubkey_bytes).unwrap();
        let receiver_pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
        let receiver_public_key = PublicKey::from_slice(&receiver_pubkey_bytes).unwrap();
        let message = OutputMessage::consensus_decode(&mut d)?;
        let range_proof : [u8;  675] = Decodable::consensus_decode(&mut d)?;
        let signature: [u8; 64] = Decodable::consensus_decode(&mut d)?;
        return Ok(
            Output { 
                commitment, 
                sender_public_key, 
                receiver_public_key, 
                message, 
                range_proof,
                signature 
            }
        );
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(&mut d)?;
        let standard_fields =
            if features & (OutputFeatures::StandardFieldsFeatureBit as u8) != 0 {
                let pubkey_bytes : [u8; 33] = Decodable::consensus_decode(&mut d)?;
                let key_exchange_pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
                let view_tag = u8::consensus_decode(&mut d)?;
                let masked_value = u64::consensus_decode(&mut d)?;
                let masked_nonce: [u8; 16] = Decodable::consensus_decode(&mut d)?;
                Some(
                    OutputMessageStandardFields{
                        key_exchange_pubkey,
                        view_tag,
                        masked_value,
                        masked_nonce})
            } else {
                None
            };
        let extra_data: Vec<u8> =
            if features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
                Decodable::consensus_decode(&mut d)?
            }
            else {
                vec! []
            };
        return Ok(OutputMessage{features, standard_fields, extra_data});
    }
}

impl Encodable for OutputMessage {
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(&mut writer)?;
        match self.standard_fields {
            Some(ref fields) => {
                len += fields.key_exchange_pubkey.serialize().consensus_encode(&mut writer)?;
                len += fields.view_tag.consensus_encode(&mut writer)?;
                len += fields.masked_value.consensus_encode(&mut writer)?;
                len += fields.masked_nonce.consensus_encode(&mut writer)?;
            }
            None => {}
        }
        if self.features & (OutputFeatures::ExtraDataFeatureBit as u8) != 0 {
            len += self.extra_data.consensus_encode(&mut writer)?;
        }
        return Ok(len);
    }
}
