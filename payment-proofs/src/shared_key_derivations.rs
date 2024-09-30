// This is copied from monero-wallet. monero-wallet should make this pub, allowing us to
// deduplicate this code. TODO

use std_shims::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{Scalar, EdwardsPoint};

use monero_wallet::{
  io::write_varint,
  primitives::{Commitment, keccak256, keccak256_to_scalar},
  ringct::EncryptedAmount,
  transaction::Input,
};

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub(crate) struct SharedKeyDerivations {
  // Hs("view_tag" || 8Ra || o)
  pub(crate) view_tag: u8,
  // Hs(uniqueness || 8Ra || o) where uniqueness may be empty
  pub(crate) shared_key: Scalar,
}

impl SharedKeyDerivations {
  // https://gist.github.com/kayabaNerve/8066c13f1fe1573286ba7a2fd79f6100
  pub(crate) fn uniqueness(inputs: &[Input]) -> [u8; 32] {
    let mut u = b"uniqueness".to_vec();
    for input in inputs {
      match input {
        // If Gen, this should be the only input, making this loop somewhat pointless
        // This works and even if there were somehow multiple inputs, it'd be a false negative
        Input::Gen(height) => {
          write_varint(height, &mut u).unwrap();
        }
        Input::ToKey { key_image, .. } => u.extend(key_image.compress().to_bytes()),
      }
    }
    keccak256(u)
  }

  #[allow(clippy::needless_pass_by_value)]
  pub(crate) fn output_derivations(
    uniqueness: Option<[u8; 32]>,
    ecdh: Zeroizing<EdwardsPoint>,
    o: usize,
  ) -> Zeroizing<SharedKeyDerivations> {
    // 8Ra
    let mut output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
    );

    // || o
    {
      let output_derivation: &mut Vec<u8> = output_derivation.as_mut();
      write_varint(&o, output_derivation).unwrap();
    }

    let view_tag = keccak256([b"view_tag".as_ref(), &output_derivation].concat())[0];

    // uniqueness ||
    let output_derivation = if let Some(uniqueness) = uniqueness {
      Zeroizing::new([uniqueness.as_ref(), &output_derivation].concat())
    } else {
      output_derivation
    };

    Zeroizing::new(SharedKeyDerivations {
      view_tag,
      shared_key: keccak256_to_scalar(&output_derivation),
    })
  }

  // H(8Ra || 0x8d)
  #[allow(clippy::needless_pass_by_value)]
  pub(crate) fn payment_id_xor(ecdh: Zeroizing<EdwardsPoint>) -> [u8; 8] {
    // 8Ra
    let output_derivation = Zeroizing::new(
      Zeroizing::new(Zeroizing::new(ecdh.mul_by_cofactor()).compress().to_bytes()).to_vec(),
    );

    let mut payment_id_xor = [0; 8];
    payment_id_xor
      .copy_from_slice(&keccak256([output_derivation.as_ref(), [0x8d].as_ref()].concat())[.. 8]);
    payment_id_xor
  }

  pub(crate) fn commitment_mask(&self) -> Scalar {
    let mut mask = b"commitment_mask".to_vec();
    mask.extend(self.shared_key.as_bytes());
    let res = keccak256_to_scalar(&mask);
    mask.zeroize();
    res
  }

  pub(crate) fn compact_amount_encryption(&self, amount: u64) -> [u8; 8] {
    let mut amount_mask = Zeroizing::new(b"amount".to_vec());
    amount_mask.extend(self.shared_key.to_bytes());
    let mut amount_mask = keccak256(&amount_mask);

    let mut amount_mask_8 = [0; 8];
    amount_mask_8.copy_from_slice(&amount_mask[.. 8]);
    amount_mask.zeroize();

    (amount ^ u64::from_le_bytes(amount_mask_8)).to_le_bytes()
  }

  pub(crate) fn decrypt(&self, enc_amount: &EncryptedAmount) -> Commitment {
    match enc_amount {
      EncryptedAmount::Original { mask, amount } => {
        let mask_shared_sec = keccak256(self.shared_key.as_bytes());
        let mask =
          Scalar::from_bytes_mod_order(*mask) - Scalar::from_bytes_mod_order(mask_shared_sec);

        let amount_shared_sec = keccak256(mask_shared_sec);
        let amount_scalar =
          Scalar::from_bytes_mod_order(*amount) - Scalar::from_bytes_mod_order(amount_shared_sec);
        // d2b from rctTypes.cpp
        let amount = u64::from_le_bytes(amount_scalar.to_bytes()[0 .. 8].try_into().unwrap());

        Commitment::new(mask, amount)
      }
      EncryptedAmount::Compact { amount } => Commitment::new(
        self.commitment_mask(),
        u64::from_le_bytes(self.compact_amount_encryption(u64::from_le_bytes(*amount))),
      ),
    }
  }
}
