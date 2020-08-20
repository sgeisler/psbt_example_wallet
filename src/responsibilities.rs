use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Address, Amount, Script, TxOut};
use secp256k1::{Message, Signature};
use std::fmt::Debug;

/// This trait corresponds to the Creator and Updater responsibility described in
/// [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki#creator). As noted
/// there the both functionalities are most often combined as the creator most likely has more meta
/// information about the transaction they are creating and is thus able to put it into the PSBT
/// (which otherwise would be a separate update step).
pub trait PsbtWallet {
    /// Wallet backend specific errors like database connection errors that aren't captured in
    /// `PsbtCreationError`.
    type Error: Debug;

    /// Create a transaction that pays a set of outputs.
    fn create_transaction(
        &mut self,
        outputs: &[TxOut],
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>>;

    /// Creates a transaction that pays a certain `amount` to a `script` and keeps the change
    fn pay_to_script(
        &mut self,
        script_pk: Script,
        amount: Amount,
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>> {
        self.create_transaction(&[TxOut {
            value: amount.as_sat(),
            script_pubkey: script_pk,
        }])
    }

    /// Creates a transaction that pays a certain `amount` to an `address` and keeps the change
    fn pay_to_address(
        &mut self,
        address: Address,
        amount: Amount,
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>> {
        self.pay_to_script(address.script_pubkey(), amount)
    }
}

/// Common errors when creating a transaction
#[derive(Debug)]
pub enum PsbtCreationError<E: Debug> {
    /// The wallet doens't control a sufficient amount of Bitcoins to fund the transaction
    InsufficientFunds,
    /// One of the outputs has a value below the dust limit
    OutputBelowDustLimit,
    /// Too many outputs were supplied
    TooManyOutputs,
    /// Wallet backend error
    WalletError(E),
}

/// A signer capable of signing PSBTs. This can either be a software signer (see the implementation
/// for `ExtendedSecretKey`) or a hardware device.
pub trait SignPsbt {
    /// Signing backend error type
    type Error: Debug;

    /// PSBT validation function that can be used by custom signers too
    fn validate(&self, psbt: &PartiallySignedTransaction) -> Result<(), PsbtValidationError> {
        // default validator impl
        Ok(())
    }

    /// Signs all inputs for which it controls the keys and adds the signatures to the PSBT
    fn sign_psbt(
        &mut self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, PsbtSignError<Self::Error>>;
}

/// Common errors in the signing stage
#[derive(Debug)]
pub enum PsbtSignError<E: Debug> {
    /// The PSBT is not valid for signig according to BIP-174
    ValidationError(PsbtValidationError),
    /// Error of the signing backend
    BackendError(E),
}

/// Errors that can happen when validating a PSBT before signing
#[derive(Debug)]
pub enum PsbtValidationError {}

impl<T, E> SignPsbt for T
where
    T: Fn(Message, Fingerprint, DerivationPath) -> Result<Option<Signature>, E>,
    E: Debug,
{
    type Error = E;

    fn sign_psbt(
        &mut self,
        mut psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, PsbtSignError<Self::Error>> {
        self.validate(&psbt)
            .map_err(PsbtSignError::ValidationError)?;

        let mut hasher = bitcoin::util::bip143::SigHashCache::new(&psbt.global.unsigned_tx);

        for (input_idx, input) in psbt.inputs.iter_mut().enumerate() {
            for (pk, (fp, path)) in input.hd_keypaths.iter() {
                let sighash_type = input.sighash_type.map(|sht| sht.as_u32()).unwrap_or(1);

                let script = &input.witness_utxo.as_ref().unwrap().script_pubkey;

                let script_code = if script.is_v0_p2wpkh() {
                    let mut script_code = vec![0x76u8, 0xa9, 0x14];
                    script_code.extend_from_slice(&script[2..]);
                    script_code.extend_from_slice(&[0x88, 0xac]);
                    script_code
                } else if script.is_v0_p2wsh() {
                    input.witness_script.as_ref().unwrap().to_bytes()
                } else {
                    unimplemented!()
                };

                let sig_hash = hasher.signature_hash(
                    input_idx,
                    &script_code.into(),
                    input.witness_utxo.as_ref().unwrap().value,
                    input.sighash_type.unwrap(),
                );

                // TODO: impl 32bytes hash for hash newtypes
                let msg = Message::from_slice(&sig_hash[..]).unwrap();
                let sig: Signature = match self(msg, (*fp).clone(), path.clone())
                    .map_err(|e| PsbtSignError::BackendError(e))?
                {
                    Some(sig) => sig,
                    None => continue, // ignore keys we can't sign for
                };

                let mut sig_bytes = sig.serialize_der().to_vec();
                sig_bytes.push(sighash_type as u8); // TODO: is this sane?
                input.partial_sigs.insert(*pk, sig_bytes);
            }
        }

        Ok(psbt)
    }
}

impl SignPsbt for ExtendedPrivKey {
    type Error = secp256k1::Error;

    fn sign_psbt(
        &mut self,
        psbt: PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, PsbtSignError<Self::Error>> {
        let mut sign_closure = |msg, fp, path| -> Result<Option<Signature>, Self::Error> {
            let ctx = secp256k1::Secp256k1::new();
            if self.fingerprint(&ctx) != fp {
                return Ok(None);
            }

            let key = match self.derive_priv(&ctx, &path) {
                Ok(key) => key,
                Err(bitcoin::util::bip32::Error::Ecdsa(e)) => return Err(e),
                _ => unreachable!(),
            };

            Ok(Some(ctx.sign(&msg, &key.private_key.key)))
        };
        sign_closure.sign_psbt(psbt)
    }
}
