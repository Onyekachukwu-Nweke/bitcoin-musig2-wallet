// use musig2::{KeyAggContext, secp256k1::PublicKey, AggNonce, PartialSignature, aggregate_partial_signatures};
// use musig2::secp256k1::Message;
// use musig2::secp256k1::schnorr::Signature;
//
// pub struct Coordinator {
//     pub key_agg_ctx: KeyAggContext,
// }
//
// impl Coordinator {
//     pub fn new(mut pubkeys: Vec<PublicKey>) -> Self {
//         pubkeys.sort();
//         let key_agg_ctx = KeyAggContext::new(pubkeys).expect(
//             "Failed to create KeyAggContext");
//         Self { key_agg_ctx }
//     }
//
//     pub fn aggregated_public_key(&self) -> PublicKey {
//         self.key_agg_ctx.aggregated_pubkey_untweaked()
//     }
//
//     pub fn aggregate_signatures(
//         &self,
//         aggregated_nonce: &AggNonce,
//         partial_signatures: Vec<PartialSignature>,
//         message: &[u8],
//     ) -> Signature {
//         let msg = Message::from(message);
//         aggregate_partial_signatures(
//             &self.key_agg_ctx,
//             aggregated_nonce,
//             partial_signatures,
//             &msg,
//         ).expect("Signature aggregation failed")
//     }
// }
