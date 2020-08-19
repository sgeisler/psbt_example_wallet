use crate::responsibilities::{PsbtCreationError, PsbtWallet, SignPsbt};
use bip39::Mnemonic;
use bitcoin::blockdata::constants::max_target;
use bitcoin::consensus::Encodable;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{
    ChildNumber, DerivationPath, DerivationPathIterator, ExtendedPrivKey, ExtendedPubKey,
    Fingerprint,
};
use bitcoin::util::misc::script_find_and_remove;
use bitcoin::util::psbt::{Input, PartiallySignedTransaction};
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, Script, SigHashType, Transaction, TxIn, TxOut,
    Txid,
};
use bitcoincore_rpc::bitcoincore_rpc_json::{ScanTxoutRequest, ScanUtxoResult, Utxo};
use bitcoincore_rpc::{Auth, Client, Error, RpcApi};
use itertools::zip;
use miniscript::descriptor::DescriptorPublicKey;
use miniscript::Descriptor;
use secp256k1::{Message, Signature};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::net::TcpStream;
use std::str::FromStr;
use structopt::StructOpt;

mod responsibilities;

const DUST_LIMIT: u64 = 546;

pub struct NaiveWallet {
    descriptor: Descriptor<DescriptorPublicKey>,
    utxos: Vec<(DerivationPath, Utxo)>,
    network: Network,
    rpc: bitcoincore_rpc::Client,
    feerate_sat_byte: f64,
    gap_limit: u64,
    internal_next_key: ChildNumber,
    external_next_key: ChildNumber,
}

impl NaiveWallet {
    pub fn new(
        descriptor: Descriptor<DescriptorPublicKey>,
        network: Network,
        rpc: bitcoincore_rpc::Client,
        gap_limit: u64,
    ) -> Result<NaiveWallet, bitcoincore_rpc::Error> {
        let internal = DerivationPath::from(&[ChildNumber::from_normal_idx(1).unwrap()][..]);
        let mut internal_it = internal.normal_children();
        let external = DerivationPath::from(&[ChildNumber::from_normal_idx(0).unwrap()][..]);
        let mut external_it = external.normal_children();

        let utxos: Vec<(DerivationPath, Utxo)> =
            Self::fetch_utxos(&rpc, &descriptor, &mut internal_it, gap_limit)
                .chain(Self::fetch_utxos(
                    &rpc,
                    &descriptor,
                    &mut external_it,
                    gap_limit,
                ))
                .collect::<Result<_, _>>()?;

        fn child_num_sub(child: ChildNumber, sub: u32) -> ChildNumber {
            match child {
                ChildNumber::Normal { index } => ChildNumber::Normal { index: index - sub },
                ChildNumber::Hardened { index } => ChildNumber::Hardened { index: index - sub },
            }
        }

        Ok(NaiveWallet {
            descriptor,
            utxos,
            network,
            rpc,
            feerate_sat_byte: 1.0,
            gap_limit,
            internal_next_key: child_num_sub(internal_it.next().unwrap()[..][1], gap_limit as u32),
            external_next_key: child_num_sub(external_it.next().unwrap()[..][1], gap_limit as u32),
        })
    }

    fn fetch_utxos<'a, 'b: 'a>(
        rpc: &'a Client,
        descriptor: &'a Descriptor<DescriptorPublicKey>,
        children: &'a mut DerivationPathIterator<'b>,
        gap_limit: u64,
    ) -> FetchUtxoIterator<'a, 'b> {
        FetchUtxoIterator {
            rpc,
            descriptor,
            children,
            gap_limit,
            last_res: (DerivationPath::from(&[][..]), vec![]),
            net: Network::Regtest,
        }
    }

    fn descriptor_utxo_to_input(
        utxo: Utxo,
        desc: Descriptor<DescriptorPublicKey>,
        path: DerivationPath,
    ) -> Input {
        let ctx = Secp256k1::new();
        let mut hd_keypaths = BTreeMap::default();
        desc.translate_pk(
            |pk| -> Result<_, ()> {
                match pk {
                    DescriptorPublicKey::XPub(xpub) => {
                        if let Some((fp, base_path)) = xpub.source.clone() {
                            // TODO: impl DerivationPath concat
                            let mut path: Vec<ChildNumber> = base_path.into();
                            path.extend_from_slice(&xpub.derivation_path[..]);
                            // TODO: impl path ffunction for DescriptorXKey
                            // TODO: impl get real key
                            hd_keypaths.insert(
                                xpub.xkey
                                    .derive_pub(&ctx, &xpub.derivation_path)
                                    .unwrap()
                                    .public_key,
                                (fp, path.into()),
                            );
                        } else {
                            hd_keypaths.insert(
                                xpub.xkey
                                    .derive_pub(&ctx, &xpub.derivation_path)
                                    .unwrap()
                                    .public_key,
                                (xpub.xkey.fingerprint(), xpub.derivation_path.clone()),
                            );
                        }
                    }
                    DescriptorPublicKey::PubKey(_) => {}
                }
                Ok(String::new())
            },
            |_| Ok(String::new()),
        );

        let mut input = Input {
            non_witness_utxo: None,
            witness_utxo: None,
            partial_sigs: Default::default(),
            sighash_type: Some(SigHashType::All),
            redeem_script: None,
            witness_script: None,
            hd_keypaths,
            final_script_sig: None,
            final_script_witness: None,
            unknown: Default::default(),
        };

        match desc {
            Descriptor::Bare(_) => unimplemented!(),
            Descriptor::Pk(_) => unimplemented!(),
            Descriptor::Pkh(_) => unimplemented!(),
            Descriptor::Wpkh(_) => {
                input.witness_utxo = Some(TxOut {
                    value: utxo.amount.as_sat(),
                    script_pubkey: utxo.script_pub_key,
                });
            }
            Descriptor::ShWpkh(_) => unimplemented!(),
            Descriptor::Sh(_) => unimplemented!(),
            Descriptor::Wsh(_) => unimplemented!(),
            Descriptor::ShWsh(_) => unimplemented!(),
        }

        input
    }

    pub fn total_funds(&self) -> Amount {
        let funds: u64 = self
            .utxos
            .iter()
            .map(|(_, utxo)| utxo.amount.as_sat())
            .sum();
        Amount::from_sat(funds)
    }

    pub fn new_addr(&mut self) -> Address {
        let descr = self
            .descriptor
            .derive(&[ChildNumber::Normal { index: 0 }, self.external_next_key][..]);
        self.external_next_key = self.external_next_key.increment().unwrap();

        descr.address(self.network).unwrap()
    }

    fn new_change_addr(&mut self) -> Address {
        let descr = self
            .descriptor
            .derive(&[ChildNumber::Normal { index: 1 }, self.internal_next_key][..]);
        self.internal_next_key = self.internal_next_key.increment().unwrap();

        descr.address(self.network).unwrap()
    }
}

pub struct FetchUtxoIterator<'a, 'b: 'a> {
    rpc: &'a Client,
    descriptor: &'a Descriptor<DescriptorPublicKey>,
    children: &'a mut DerivationPathIterator<'b>,
    gap_limit: u64,
    last_res: (DerivationPath, Vec<Utxo>),
    net: Network,
}

impl<'a, 'b: 'a> Iterator for FetchUtxoIterator<'a, 'b> {
    type Item = bitcoincore_rpc::Result<(DerivationPath, Utxo)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut gap = 0;
        while self.last_res.1.is_empty() {
            if gap >= self.gap_limit {
                return None;
            }

            let path = self
                .children
                .next()
                .expect("infinite iterator for all intents and purposes");
            let script = self.descriptor.derive(&path[..]).script_pubkey();

            let utxos = match self
                .rpc
                .scan_txout_set(&[ScanTxoutRequest::Single(format!("raw({:x})", script))])
            {
                Ok(utxos) => utxos,
                Err(e) => return Some(Err(e)),
            };
            self.last_res = (path, utxos.unspents);
            gap += 1;
        }

        return Some(Ok((
            self.last_res.0.clone(),
            self.last_res
                .1
                .pop()
                .expect("can't be empty, see while loop"),
        )));
    }
}

impl PsbtWallet for NaiveWallet {
    type Error = &'static str;

    fn create_transaction(
        &mut self,
        mut outputs: &[TxOut],
    ) -> Result<PartiallySignedTransaction, PsbtCreationError<Self::Error>> {
        // TODO: discuss making the argument a vec
        let mut outputs = outputs.to_vec();

        // TODO: calculate size, increase when adding inputs
        let size_est_bytes = 400;
        let min_amt_sat = outputs.iter().map(|out| out.value).sum::<u64>()
            + ((self.feerate_sat_byte * size_est_bytes as f64) as u64);

        let mut selected_utxos = vec![];
        let mut in_sats = 0;
        while let Some(utxo) = self.utxos.pop() {
            in_sats += utxo.1.amount.as_sat();
            selected_utxos.push(utxo);

            if in_sats >= min_amt_sat {
                break;
            }
        }

        if in_sats < min_amt_sat {
            return Err(PsbtCreationError::InsufficientFunds);
        }

        if in_sats - min_amt_sat > DUST_LIMIT {
            outputs.push(TxOut {
                value: in_sats - min_amt_sat,
                script_pubkey: self.new_change_addr().script_pubkey(),
            });
        }

        let unsinged_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: selected_utxos
                .iter()
                .map(|(deriv, utxo)| TxIn {
                    previous_output: OutPoint::new(utxo.txid, utxo.vout),
                    script_sig: Script::new(),
                    sequence: 0,
                    witness: vec![],
                })
                .collect(),
            output: outputs,
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsinged_tx).unwrap();

        for ((deriv, utxo), input) in zip(selected_utxos, psbt.inputs.iter_mut()) {
            *input = Self::descriptor_utxo_to_input(
                utxo,
                self.descriptor.derive(deriv.as_ref()),
                deriv.clone(),
            );
        }

        Ok(psbt)
    }
}

pub fn finalize(mut psbt: PartiallySignedTransaction) -> PartiallySignedTransaction {
    for input in psbt.inputs.iter_mut() {
        if let Some(utxo) = &input.witness_utxo {
            assert!(utxo.script_pubkey.is_v0_p2wpkh());
            assert_eq!(input.partial_sigs.len(), 1);
            let (key, sig) = input.partial_sigs.iter().next().unwrap();

            let witness = vec![sig.clone(), key.to_bytes()];
            input.final_script_witness = Some(witness);
        } else {
            unimplemented!()
        }
    }
    psbt
}

fn print_psbt(psbt: &PartiallySignedTransaction) {
    let mut psbt_bytes = vec![];
    psbt.consensus_encode(&mut psbt_bytes).unwrap();
    println!("psbt: {}", base64::encode(psbt_bytes));
}

#[derive(StructOpt)]
enum Command {
    List,
    NewAddr,
    Send { recipient: Address, amount: Amount },
}

fn main() {
    let cmd: Command = Command::from_args();

    let ctx = secp256k1::Secp256k1::new();

    let mut xpriv = ExtendedPrivKey::from_str("tprv8ZgxMBicQKsPe2z4yh5peQ8VUQpvcmNH3zQ1gP7h3X41KWP76opG9BjVywxV2WfhxoVbEFfVjD6jjmR7ZM9NUBqQZmrhY1EuvbVQqY4VYKV").unwrap();
    let xpub = ExtendedPubKey::from_private(&ctx, &xpriv);

    let rpc = bitcoincore_rpc::Client::new(
        "http://127.0.0.1:18443".into(),
        Auth::UserPass("bitcoin".into(), "bitcoin".into()),
    )
    .unwrap();

    let mut wallet = NaiveWallet::new(
        format!("wpkh({}/*)", &xpub).parse().unwrap(),
        Network::Regtest,
        rpc,
        10,
    )
    .unwrap();

    match cmd {
        Command::List => {
            println!("descriptor: {}", &wallet.descriptor);
            println!("funds: {} BTC", wallet.total_funds().as_btc());
        }
        Command::NewAddr => {
            println!("{}", wallet.new_addr());
        }
        Command::Send { recipient, amount } => {
            let tx = wallet
                .create_transaction(&[TxOut {
                    value: amount.as_sat(),
                    script_pubkey: recipient.script_pubkey(),
                }])
                .unwrap();

            print!("created ");
            print_psbt(&tx);

            let signed_tx = xpriv.sign_psbt(tx).unwrap();
            print!("signed ");
            print_psbt(&signed_tx);

            let finalized_psbt = finalize(signed_tx);
            print!("finalized ");
            print_psbt(&finalized_psbt);

            let mut tx_bytes = vec![];
            let tx = finalized_psbt.extract_tx();
            tx.consensus_encode(&mut tx_bytes).unwrap();
            println!("tx: {}", hex::encode(&tx_bytes));

            println!("{:?}", wallet.rpc.send_raw_transaction(&tx_bytes));
        }
    }
}
