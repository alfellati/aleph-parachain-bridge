use codec::{Decode, Encode};
use sp_runtime::{traits::Header as HeaderT, RuntimeDebug};

use sp_std::{vec, vec::Vec};

use crate::AuthoritySignature;
use scale_info::TypeInfo;

#[derive(TypeInfo, PartialEq, Eq, Clone, Debug, Decode, Encode)]
pub struct Signature(AuthoritySignature);

// This could be pulled from aleph_bft_cryto, but we need to implement TypeInfo for it.
// TODO: add TypeInfo to aleph_bft_crypto::NodeMap and reuse it here.
#[derive(TypeInfo, Clone, Eq, PartialEq, Debug, Default, Decode, Encode)]
pub struct SignatureSet(Vec<Option<Signature>>);

impl SignatureSet {
	/// Constructs a new node map with a given length.
	pub fn with_size(len: usize) -> Self {
		let v = vec![None; len];
		SignatureSet(v)
	}

	pub fn size(&self) -> usize {
		self.0.len()
	}

	pub fn iter(&self) -> impl Iterator<Item = (usize, &Signature)> {
		self.0
			.iter()
			.enumerate()
			.filter_map(|(idx, maybe_value)| Some((idx, maybe_value.as_ref()?)))
	}

	pub fn get(&self, node_id: usize) -> Option<&Signature> {
		self.0[node_id].as_ref()
	}

	pub fn insert(&mut self, node_id: usize, value: Signature) {
		self.0[node_id] = Some(value)
	}
}

/// A proof of block finality, currently in the form of a sufficiently long list of signatures or a
/// sudo signature of a block for emergency finalization.
#[derive(TypeInfo, Clone, Encode, Decode, Debug, PartialEq, Eq)]
pub enum AlephJustification {
	CommitteeMultisignature(SignatureSet),
	EmergencySignature(AuthoritySignature),
}

#[derive(Encode, Decode, RuntimeDebug, Clone, PartialEq, Eq)]
pub struct AlephFullJustification<Header: HeaderT> {
	header: Header,
	justification: AlephJustification,
}

impl<Header: HeaderT> AlephFullJustification<Header> {
	pub fn new(header: Header, justification: AlephJustification) -> Self {
		Self { header, justification }
	}

	pub fn header(&self) -> &Header {
		&self.header
	}

	pub fn justification(&self) -> &AlephJustification {
		&self.justification
	}

	pub fn into_justification(self) -> AlephJustification {
		self.justification
	}

	pub fn into_header(self) -> Header {
		self.header
	}
}

impl<H: HeaderT> bp_header_chain::FinalityProof<H::Number> for AlephFullJustification<H> {
	fn target_header_number(&self) -> H::Number {
		*self.header().number()
	}
}
