use codec::{Decode, Encode, Input, MaxEncodedLen};
use sp_runtime::{traits::Header as HeaderT, EncodedJustification, RuntimeAppPublic, RuntimeDebug};

use crate::{AuthoritySet, AuthoritySignature};

#[derive(PartialEq, Eq, Clone, Debug, Hash, Decode, Encode)]
pub struct Signature(AuthoritySignature);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Encode, Decode)]
pub struct SignatureSet<Signature>(pub aleph_bft_crypto::SignatureSet<Signature>);

/// A proof of block finality, currently in the form of a sufficiently long list of signatures or a
/// sudo signature of a block for emergency finalization.
#[derive(Clone, Decode, Debug, PartialEq, Eq)]
pub enum AlephJustification {
	CommitteeMultisignature(SignatureSet<Signature>),
	EmergencySignature(AuthoritySignature),
}

#[derive(RuntimeDebug, Clone, PartialEq, Eq)]
pub struct AlephFullJustification<Header: HeaderT> {
	header: Header,
	justification: AlephJustification,
}

#[derive(Eq, Decode, PartialEq, Debug, Copy, Clone)]
pub struct Version(pub u16);

pub fn decode_versioned_aleph_justification<I: Input>(
	input: &mut I,
) -> Result<AlephJustification, Error> {
	let version = Version::decode(input).map_err(|_| Error::JustificationNotDecodable)?;
	let num_bytes = u16::decode(input).map_err(|_| Error::JustificationNotDecodable)?;
	match version {
		Version(3) =>
			Ok(AlephJustification::decode(input).map_err(|_| Error::JustificationNotDecodable)?),
		_ => Err(Error::UnsupportedJustificationVersion),
	}
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

	pub fn justification_mut(&mut self) -> &mut AlephJustification {
		&mut self.justification
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

#[derive(Eq, RuntimeDebug, PartialEq)]
pub enum Error {
	UnsupportedJustificationVersion,
	JustificationNotDecodable,
	NotEnoughCorrectSignatures,
	InvalidIndex,
	Emergency,
}

pub fn verify_justification<Header: HeaderT>(
	authority_set: &AuthoritySet,
	justification: &AlephFullJustification<Header>,
) -> Result<(), Error> {
	match justification.justification() {
		AlephJustification::CommitteeMultisignature(signature_set) => {
			let mut signatures = signature_set.0.iter();
			let mut signature_count = 0;

			while let Some((index, signature)) = signatures.next() {
				let authority = authority_set.get(index.0).ok_or(Error::InvalidIndex)?;

				if authority.verify(&justification.header().encode(), &signature.0) {
					signature_count += 1;
				}
			}

			if signature_count < 2 * authority_set.len() / 3 + 1 {
			 	return Err(Error::NotEnoughCorrectSignatures)
			} else {
				panic!("{:?}", signature_count);
			}

			Ok(())
		},
		AlephJustification::EmergencySignature(_) => Err(Error::Emergency),
	}
}

// Tests
#[cfg(test)]
mod tests {
	use super::*;
	use crate::AuthorityId;
	use bp_test_utils::test_header;
	use hex::FromHex;
	use serde::Deserialize;
	use sp_application_crypto::Pair;
	use sp_core::H256;
	use sp_runtime::{testing::Header, traits::BlakeTwo256, Digest, DigestItem, ConsensusEngineId};

	fn generate_seeds(size: usize) -> Vec<[u8; 32]> {
		let mut seed = [0u8; 32];
		let mut seeds = Vec::new();
		for i in 0..size {
			seed[i] = 1;
			seeds.push(seed);
		}
		seeds
	}

	fn authority_id_from_seed(s: &[u8; 32]) -> AuthorityId {
		pair_from_seed(s).public()
	}

	fn pair_from_seed(s: &[u8; 32]) -> crate::app::Pair {
		crate::app::Pair::from_seed(s)
	}

	fn authority_set(seeds: Vec<[u8; 32]>) -> AuthoritySet {
		let mut authority_set = AuthoritySet::new();
		for authority in seeds.iter() {
			authority_set.push(authority_id_from_seed(authority));
		}
		authority_set
	}

	fn generate_default_signature_set(header: &Header) -> SignatureSet<Signature> {
		use aleph_bft_crypto::{NodeCount, NodeIndex, NodeMap};
		use std::collections::HashMap;

		let mut hashmap = HashMap::new();
		for (index, authority) in generate_seeds(4).iter().enumerate() {
			let aleph_authority = pair_from_seed(authority);
			let signature = aleph_authority.sign(&header.encode());
			hashmap.insert(NodeIndex(index), Signature(signature));
		}

		SignatureSet(NodeMap::from_hashmap(NodeCount(4), hashmap))
	}

	fn default_test_justification() -> AlephFullJustification<sp_runtime::testing::Header> {
		let header = test_header(5);
		let signature_set = generate_default_signature_set(&header);
		let justification = AlephJustification::CommitteeMultisignature(signature_set);

		AlephFullJustification::new(header, justification)
	}

	#[test]
	fn accepts_valid_justification() {
		let justification = default_test_justification();
		let authority_set = authority_set(generate_seeds(4));

		assert!(verify_justification(&authority_set, &justification).is_ok());
	}

	/*#[test]
	fn rejects_emergency_justification() {
		use crate::aleph_justification::tests::generate_emergency_justification;

		let justification = generate_emergency_justification();
		let authority_set = justification.authority_set();

		assert!(verify_justification(&authority_set, &justification).is_err());
	}*/

	#[test]
	fn rejects_justification_with_too_little_signatures() {
		let justification = default_test_justification();
		let authority_set = authority_set(generate_seeds(6));

		assert!(verify_justification(&authority_set, &justification).is_err());
	}

	/*#[test]
	fn rejects_duplicate_signatures() {
		use crate::aleph_justification::tests::generate_valid_justification;

		let mut justification = generate_valid_justification();
		let authority_set = justification.authority_set();

		let signature = justification.justification().signature_set().0[0].clone();
		justification.justification_mut().signature_set_mut().0.push(signature);

		assert!(verify_justification(&authority_set, &justification).is_err());
	}*/

	#[test]
	fn incorrect_indices() {
		let justification = default_test_justification();
		let authority_set = authority_set(generate_seeds(3));

		assert!(verify_justification(&authority_set, &justification).is_err());
	}

	fn decode_from_hex<D: Decode>(data: &str) -> D {
		Decode::decode(&mut &Vec::from_hex(data).unwrap()[..]).unwrap()
	}

	const AURA_ENGINE_ID: ConsensusEngineId = [b'a', b'u', b'r', b'a'];

	const DEVNET_JUSTIFICATION: &str = "0300c6000010016e444638b5437a4cd3efc0f926e8738f02ce837ff0cd48d4caec31dda0c295ea15613bfddb91823e77c2303ba6b1b7dd1789c9698144bfb87878c52e49aa300e0001436254d359bf6c8342cdc95141d07a06b53d2355ac734175c332c5fe767d3b3b752d3010ca44d6b9a11cab1ca723d2ffdcb706dceeda0cfb5db2475f3c27b80c0115cf4588ed5862cfe5c6596f678f7811272ecb0eb96d9349e6443d4b2449f46f725869b2c0af17c19854737839c357282d5dbbe8324de00c85a66d3005904602";
	/*const DEVNET_HEADER: Header = Header::new(
			51730103,
			BlakeTwo256::decode(FromHex::from_hex("78d422f744c6207f40ceb5504021803a7551c03e74b3e2c847df2a052b565942")),
			BlakeTwo256::decode(FromHex::from_hex("ffa33bb51a943ebd44426569cbfc901ca1e37a8f06652cf5cff20473cd980690")),
			BlakeTwo256::decode(FromHex::from_hex("de7ce2d09b3d3b6decfdf9a1e8b0582d413642d8edd4d326a5677f6222027028")),
			Digest {
				logs: vec![
				DigestItem::PreRuntime(AURA_ENGINE_ID, Vec::decode(FromHex::from_hex("b1b8a26400000000").unwrap())),
				DigestItem::Seal(AURA_ENGINE_ID, Vec::decode(FromHex::from_hex("220b93bbbb5af5352c2da639536b2c0ac33e6cfe4d765846f33838344e24fb54373092c0b16671414d431828ddb771552e17a89a67928e88e5ac343a0021548e").unwrap()))
			]}
		);
	const DEVNET_AUTHORITIES: [&str; 4] = [
		"8960ce7da9896de4204a6b565c357bd62743126d65b16b298b9e31b7d3045cd7",
		"976306673bd098fca2238a193b506d6abc7340849923a9967c4403e48fb43f33",
		"0124b9b4cc0f09a561555a06e5a8888f84f5778032a1c9a7c876d8ac1816ef3d",
		"fec85f3a09540b62f545226e2c8bbbdc1eba8df10b8b9f7b8c9937d86e0a4a2a",
	];*/

	// Block 51730103
	const MAINNET_JUSTIFICATION: &str = "03009002003801752af5d2d57c25657cf083014c65eb39d18a4eeba5ca4a1ffeee378df14298ef449f9b076a3f5918de1e774410a52fb38f0fd5e70ba44dfea1453647388b94060112cb082077986f0e79bb12a69d9fa483f99f8a552e5124623a4e8a14ff324f9ba33d9b0cc11d9c773c8ee6d830a334c012f3c9b1036f44ba08f0fe5e7b1e540f01c5906221eec48d57d992573cebc1e6861f1e7e572d1d0d47328dd417361cb53d71864407246a6c0f575e67471e6692a3066d1a5787817645b9f1e5dc57fb2a0d000158b8d87262541a2f73d6c311657f74234203a3650ac442acf99bf4e1600486bb1e5849c6ac204c58c1120189c8e3c76918c564ec2a0468365751f15591580f0d0114e28c22ff3cee483567ae2fc0e4aab6386e5cba24eb3c2866b0e2245ad1a5bb70a0714e807e0b903ef58463792595a6d6a4e5fe58c3c0ad118eb031a32c7b060001c10be8f8665c804552dd3af729724422841fb47f8dfbb5487935ca86bdee3489bc03ea4c47c022462c19bb668c913392192e27f0bcc8538edf61d076c772b80600019ebf0579cd074ce2385326ad8dfadb720e14365c9cb588d56776ce9fbf73d3a4e30671fec68c6a1cee052d19ef5e018e53a44222063379f754e8aa80ea54cd05012f4b3f8a0845134fa599aea859a9c09c020712f31bf24a6e98587bf44d89f3d854df2a96c6af8ddc81885dd7c0d26f64a69f9b0da418025a6b42d955d97dcd0301e4094b019782509277dbe7969b1cb9ae22f65b7c33c32542b22ffe0d179a7661ffa3743747cf19870a1491406adb8438d11c70e5732655a340344a1c0686d20701f42cb05c7793f8055bb8c0d8e872426f2293a2cc54898548a0d71b2906caa2c4c5d5af502331c9b7c5d7e5f587414a6b5a00f92cff843d44eebb81d84a592e0400";
	const MAINNET_AUTHORITIES: [&str; 14] = [
		"3e1f808aba722e8c2b605186d525330fc0602448aa1a0e4095db3e691e82aa53",
		"4e9800a7078b680ba72b0f077d6803c3d35ccdcba15b618542801a5cdf5c949b",
		"55f42ea5496bd242dc59f3a299ebc4f3ad6ea1b47b745abdda2b3a6129cf0afe",
		"8f725daf2944ef12357e298058c317a409d313d5379fee88abddd2967b0c02da",
		"37371d98a2d7d88096414e55e861e06a07ba7645c49d446cc5e414bb3c00d456",
		"749e7ca3ff95b3c92608500525f33071cd2ce4e592ba9535a6eb7bac1b667faa",
		"c86669783d7c1c1516dd7bd70dcc893232c9a73b4e1095557ef3a929d324904a",
		"bc16685f99c1ebfbaeb0bb1b1f6b81f078977cfb5418c4e125b8a989817d9fcf",
		"8e6efcceba526685383b74cc53eb09f8fe2e6bcb9988e2bc618ead55251f7e97",
		"def643f576925be43e4e6f139c6d6787b3da8f637a3d29fef01ccaf24d82259e",
		"fb35011223beff7e82a7932bfb9f5ad0a774c9812189b0bb8aec3389b515eafc",
		"10ae993223432b051b8ecf175c2ab0ef72186b540d8abd402b0568329a5d3b03",
		"0c5b46f7d638edf0e76e85d451096f6bf361a476b43d61f177d8cf0253588cb1",
		"f4ad895cce6857c6f8b955d55907969ee6a8f177187921e771cee52bd7b2b800",
	];

	fn raw_authorities_into_authority_set(raw_authorities: &[&str]) -> AuthoritySet {
		let mut authorities = Vec::new();
		for raw_authority in raw_authorities {
			authorities.push(decode_from_hex(raw_authority));
		}
		authorities
	}

	#[test]
	fn devnet_justification_decodes() {
		let encoded_justification: Vec<u8> = FromHex::from_hex(DEVNET_JUSTIFICATION).unwrap();
		assert!(decode_versioned_aleph_justification(&mut encoded_justification.as_slice()).is_ok());
	}

	#[test]
	fn mainnet_justification_decode() {
		let encoded_justification: Vec<u8> = FromHex::from_hex(MAINNET_JUSTIFICATION).unwrap();
		assert!(decode_versioned_aleph_justification(&mut encoded_justification.as_slice()).is_ok());
	}

	/*#[test]
	fn devnet_justification_is_valid() {
		let authority_set = raw_authorities_into_authority_set(&DEVNET_AUTHORITIES);
		let encoded_justification: Vec<u8> = FromHex::from_hex(DEVNET_JUSTIFICATION).unwrap();
		let justification =
			decode_versioned_aleph_justification(&mut encoded_justification.as_slice()).unwrap();

		assert!(verify_justification(&authority_set, &justification).is_ok());
	}*/

	#[test]
	fn mainnet_justification_is_valid() {
		let authority_set = raw_authorities_into_authority_set(&MAINNET_AUTHORITIES);
		let encoded_justification: Vec<u8> = FromHex::from_hex(MAINNET_JUSTIFICATION).unwrap();
		let justification =
			decode_versioned_aleph_justification(&mut encoded_justification.as_slice()).unwrap();
		let header = Header::new(
			51730103,
			decode_from_hex("78d422f744c6207f40ceb5504021803a7551c03e74b3e2c847df2a052b565942"),
			decode_from_hex("ffa33bb51a943ebd44426569cbfc901ca1e37a8f06652cf5cff20473cd980690"),
			decode_from_hex("de7ce2d09b3d3b6decfdf9a1e8b0582d413642d8edd4d326a5677f6222027028"), 
			Digest {
				logs: vec![
				DigestItem::PreRuntime(AURA_ENGINE_ID, FromHex::from_hex("b1b8a26400000000").unwrap()), 
				DigestItem::Seal(AURA_ENGINE_ID, FromHex::from_hex("220b93bbbb5af5352c2da639536b2c0ac33e6cfe4d765846f33838344e24fb54373092c0b16671414d431828ddb771552e17a89a67928e88e5ac343a0021548e").unwrap())
			]}
		);
		let full_justification = AlephFullJustification { header, justification };

		verify_justification(&authority_set, &full_justification);

		assert!(verify_justification(&authority_set, &full_justification).is_ok());
	}
}