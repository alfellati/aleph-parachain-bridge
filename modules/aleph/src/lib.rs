// Copyright 2023 Cardinal Cryptography
// Copyright 2021 Parity Technologies (UK) Ltd.
// This file is part of Parity Bridges Common.

// Parity Bridges Common is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Bridges Common is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Bridges Common.  If not, see <http://www.gnu.org/licenses/>.

// This pallet is largely based on the `GRANDPA` pallet, but is changed to work with AlephBFT

//! Aleph bridging Pallet
//!
//! This pallet is an on-chain AlephBFT light client.
//!
//! Right now, it does not support submiting finality proofs, but only
//! being directly initialized with a header and authority set.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::large_enum_variant)]

use bp_aleph_header_chain::{ChainWithAleph, InitializationData};
use bp_header_chain::{HeaderChain, StoredHeaderData, StoredHeaderDataBuilder};
use bp_runtime::{BlockNumberOf, HashOf, HasherOf, HeaderId, HeaderOf, OwnedBridgeModule};
use frame_support::sp_runtime::traits::Header;

#[cfg(test)]
mod mock;
mod storage_types;

use storage_types::StoredAuthoritySet;

// Re-export in crate namespace for `construct_runtime!`
pub use pallet::*;

pub const LOG_TARGET: &str = "runtime::bridge-aleph";

pub type BridgedChain<T> = <T as Config>::BridgedChain;
pub type BridgedBlockNumber<T> = BlockNumberOf<<T as Config>::BridgedChain>;
pub type BridgedBlockHash<T> = HashOf<<T as Config>::BridgedChain>;
pub type BridgedBlockId<T> = HeaderId<BridgedBlockHash<T>, BridgedBlockNumber<T>>;
pub type BridgedBlockHasher<T> = HasherOf<<T as Config>::BridgedChain>;
pub type BridgedHeader<T> = HeaderOf<<T as Config>::BridgedChain>;
pub type BridgedStoredHeaderData<T> = StoredHeaderData<BridgedBlockNumber<T>, BridgedBlockHash<T>>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use bp_runtime::BasicOperatingMode;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
		type BridgedChain: ChainWithAleph;
		#[pallet::constant]
		type HeadersToKeep: Get<u32>;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(PhantomData<T>);

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
			Weight::zero()
		}
	}

	impl<T: Config> OwnedBridgeModule<T> for Pallet<T> {
		const LOG_TARGET: &'static str = LOG_TARGET;
		type OwnerStorage = PalletOwner<T>;
		type OperatingMode = BasicOperatingMode;
		type OperatingModeStorage = PalletOperatingMode<T>;
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Bootstrap the bridge pallet with an initial header and authority set from which to sync.
		///
		/// The initial configuration provided does not need to be the genesis header of the bridged
		/// chain, it can be any arbitrary header. You can also provide the next scheduled set
		/// change if it is already known.
		///
		/// This function is only allowed to be called from a trusted origin and writes to storage
		/// with practically no checks in terms of the validity of the data. It is important that
		/// you ensure that valid data is being passed in.
		///
		/// Difference with GRANDPA: This function can only be called by root.
		///
		/// Note: It cannot be called once the bridge has been initialized.
		/// To reinitialize the bridge, you must reinitialize the pallet.
		#[pallet::call_index(1)]
		#[pallet::weight((T::DbWeight::get().reads_writes(2, 5), DispatchClass::Operational))]
		pub fn initialize(
			origin: OriginFor<T>,
			init_data: super::InitializationData<BridgedHeader<T>>,
		) -> DispatchResultWithPostInfo {
			ensure_root(origin)?;

			let init_allowed = !<BestFinalized<T>>::exists();
			ensure!(init_allowed, <Error<T>>::AlreadyInitialized);
			initialize_bridge::<T>(init_data.clone())?;

			log::info!(
				target: LOG_TARGET,
				"Pallet has been initialized with the following parameters: {:?}",
				init_data
			);

			Ok(().into())
		}

		#[pallet::call_index(2)]
		#[pallet::weight((T::DbWeight::get().reads_writes(1, 1), DispatchClass::Operational))]
		pub fn set_operating_mode(
			origin: OriginFor<T>,
			operating_mode: BasicOperatingMode,
		) -> DispatchResult {
			<Self as OwnedBridgeModule<_>>::set_operating_mode(origin, operating_mode)
		}
	}

	/// Hash of the best finalized header.
	#[pallet::storage]
	#[pallet::getter(fn best_finalized)]
	pub type BestFinalized<T: Config> = StorageValue<_, BridgedBlockId<T>, OptionQuery>;

	/// A ring buffer of imported hashes. Ordered by insertion time.
	#[pallet::storage]
	pub(super) type ImportedHashes<T: Config> = StorageMap<
		Hasher = Identity,
		Key = u32,
		Value = BridgedBlockHash<T>,
		QueryKind = OptionQuery,
		OnEmpty = GetDefault,
		MaxValues = MaybeHeadersToKeep<T>,
	>;

	/// Current ring buffer position.
	#[pallet::storage]
	pub(super) type ImportedHashesPointer<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Relevant fields of imported headers.
	#[pallet::storage]
	pub type ImportedHeaders<T: Config> = StorageMap<
		Hasher = Identity,
		Key = BridgedBlockHash<T>,
		Value = BridgedStoredHeaderData<T>,
		QueryKind = OptionQuery,
		OnEmpty = GetDefault,
		MaxValues = MaybeHeadersToKeep<T>,
	>;

	/// The current Aleph Authority set.
	#[pallet::storage]
	pub type CurrentAuthoritySet<T: Config> = StorageValue<_, StoredAuthoritySet<T>, ValueQuery>;

	/// Optional pallet owner.
	///
	/// Pallet owner has the right to halt all pallet operations and then resume them. If it is
	/// `None`, then there are no direct ways to halt/resume pallet operations, but other
	/// runtime methods may still be used to do that (i.e. democracy::referendum to update halt
	/// flag directly or call the `halt_operations`).
	#[pallet::storage]
	pub type PalletOwner<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

	/// The current operating mode of the pallet.
	///
	/// Depending on the mode either all, or no transactions will be allowed.
	#[pallet::storage]
	pub type PalletOperatingMode<T: Config> = StorageValue<_, BasicOperatingMode, ValueQuery>;

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub owner: Option<T::AccountId>,
		pub init_data: Option<super::InitializationData<BridgedHeader<T>>>,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			Self { owner: None, init_data: None }
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			if let Some(ref owner) = self.owner {
				<PalletOwner<T>>::put(owner);
			}

			if let Some(init_data) = self.init_data.clone() {
				initialize_bridge::<T>(init_data).expect("genesis config is correct; qed");
			} else {
				// Since the bridge hasn't been initialized we shouldn't allow anyone to perform
				// transactions.
				<PalletOperatingMode<T>>::put(BasicOperatingMode::Halted);
			}
		}
	}

	#[pallet::event]
	pub enum Event<T: Config> {
		/// Best finalized chain header has been updated to the header with given number and hash.
		UpdatedBestFinalizedHeader { number: BridgedBlockNumber<T>, hash: BridgedBlockHash<T> },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The header being imported is older than the best finalized header known to the pallet.
		OldHeader,
		/// The pallet is not yet initialized.
		NotInitialized,
		/// The pallet has already been initialized.
		AlreadyInitialized,
		/// Too many authorities in the set.
		TooManyAuthoritiesInSet,
		/// Error generated by the `OwnedBridgeModule` trait.
		BridgeModule(bp_runtime::OwnedBridgeModuleError),
	}

	/// Import a previously verified header to the storage.
	///
	/// Note this function solely takes care of updating the storage and pruning old entries,
	/// but does not verify the validity of such import.
	fn insert_header<T: Config>(header: BridgedHeader<T>, hash: BridgedBlockHash<T>) {
		let index = <ImportedHashesPointer<T>>::get();
		let pruning = <ImportedHashes<T>>::try_get(index);
		<BestFinalized<T>>::put(HeaderId(*header.number(), hash));
		<ImportedHeaders<T>>::insert(hash, header.build());
		<ImportedHashes<T>>::insert(index, hash);

		// Update ring buffer pointer and remove old header.
		<ImportedHashesPointer<T>>::put((index + 1) % T::HeadersToKeep::get());
		if let Ok(hash) = pruning {
			log::debug!(target: LOG_TARGET, "Pruning old header: {:?}.", hash);
			<ImportedHeaders<T>>::remove(hash);
		}
	}

	/// Since this writes to storage with no real checks this should only be used in functions that
	/// were called by a trusted origin.
	fn initialize_bridge<T: Config>(
		init_params: super::InitializationData<BridgedHeader<T>>,
	) -> Result<(), Error<T>> {
		let super::InitializationData { header, authority_list, operating_mode } = init_params;
		let authority_set_length = authority_list.len();
		let authority_set = StoredAuthoritySet::<T>::try_new(authority_list)
			.map_err(|e| {
				log::error!(
					target: LOG_TARGET,
					"Failed to initialize bridge. Number of authorities in the set {} is larger than the configured value {}",
					authority_set_length,
					T::BridgedChain::MAX_AUTHORITIES_COUNT,
				);
				e
			})?;
		let initial_hash = header.hash();

		<ImportedHashesPointer<T>>::put(0);
		insert_header::<T>(*header, initial_hash);

		<CurrentAuthoritySet<T>>::put(authority_set);
		<PalletOperatingMode<T>>::put(operating_mode);

		Ok(())
	}

	/// Adapter for using `Config::HeadersToKeep` as `MaxValues` bound in our storage maps.
	pub struct MaybeHeadersToKeep<T>(PhantomData<T>);

	// this implementation is required to use the struct as `MaxValues`
	impl<T: Config> Get<Option<u32>> for MaybeHeadersToKeep<T> {
		fn get() -> Option<u32> {
			Some(T::HeadersToKeep::get())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Get the best finalized block number.
	pub fn best_finalized_number() -> Option<BridgedBlockNumber<T>> {
		BestFinalized::<T>::get().map(|id| id.number())
	}
}

/// Bridge Aleph pallet as header chain.
pub type AlephChainHeaders<T> = Pallet<T>;

impl<T: Config> HeaderChain<BridgedChain<T>> for AlephChainHeaders<T> {
	fn finalized_header_state_root(
		header_hash: HashOf<BridgedChain<T>>,
	) -> Option<HashOf<BridgedChain<T>>> {
		ImportedHeaders::<T>::get(header_hash).map(|h| h.state_root)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{
		run_test, test_header, RuntimeOrigin, System, TestHeader, TestRuntime,
		MAX_BRIDGED_AUTHORITIES,
	};
	use bp_aleph_header_chain::AuthorityId;
	use bp_runtime::{BasicOperatingMode, UnverifiedStorageProof};
	use bp_test_utils::{generate_owned_bridge_module_tests, Account, ALICE, BOB, CHARLIE};
	use frame_support::{
		assert_noop, assert_ok, dispatch::PostDispatchInfo, storage::generator::StorageValue,
	};
	use sp_runtime::DispatchError;

	fn into_authority_set(accounts: Vec<Account>) -> Vec<AuthorityId> {
		accounts.into_iter().map(|a| AuthorityId::from(a)).collect()
	}

	fn initialize_substrate_bridge() {
		System::set_block_number(1);
		System::reset_events();

		assert_ok!(init_with_origin(RuntimeOrigin::root()));
	}

	fn init_with_origin(
		origin: RuntimeOrigin,
	) -> Result<
		InitializationData<TestHeader>,
		sp_runtime::DispatchErrorWithPostInfo<PostDispatchInfo>,
	> {
		let genesis = test_header(0);

		let init_data = InitializationData {
			header: Box::new(genesis),
			authority_list: into_authority_set(vec![ALICE, BOB, CHARLIE]),
			operating_mode: BasicOperatingMode::Normal,
		};

		Pallet::<TestRuntime>::initialize(origin, init_data.clone()).map(|_| init_data)
	}

	generate_owned_bridge_module_tests!(BasicOperatingMode::Normal, BasicOperatingMode::Halted);

	#[test]
	fn init_root_origin_can_initialize_pallet() {
		run_test(|| {
			assert_ok!(init_with_origin(RuntimeOrigin::root()));
		})
	}

	#[test]
	fn init_random_user_cannot_initialize_pallet() {
		run_test(|| {
			assert_noop!(init_with_origin(RuntimeOrigin::signed(1)), DispatchError::BadOrigin);
		})
	}

	#[test]
	fn init_owner_cannot_initialize_pallet() {
		run_test(|| {
			PalletOwner::<TestRuntime>::put(2);
			assert_noop!(init_with_origin(RuntimeOrigin::signed(2)), DispatchError::BadOrigin);
		})
	}

	#[test]
	fn init_storage_entries_are_correctly_initialized() {
		run_test(|| {
			assert_eq!(BestFinalized::<TestRuntime>::get(), None,);
			assert_eq!(Pallet::<TestRuntime>::best_finalized(), None);
			assert_eq!(PalletOperatingMode::<TestRuntime>::try_get(), Err(()));

			let init_data = init_with_origin(RuntimeOrigin::root()).unwrap();

			assert!(<ImportedHeaders<TestRuntime>>::contains_key(init_data.header.hash()));
			assert_eq!(BestFinalized::<TestRuntime>::get().unwrap().1, init_data.header.hash());
			assert_eq!(
				CurrentAuthoritySet::<TestRuntime>::get().authorities,
				init_data.authority_list
			);
			assert_eq!(
				PalletOperatingMode::<TestRuntime>::try_get(),
				Ok(BasicOperatingMode::Normal)
			);
		})
	}

	#[test]
	fn init_can_only_initialize_pallet_once() {
		run_test(|| {
			initialize_substrate_bridge();
			assert_noop!(
				init_with_origin(RuntimeOrigin::root()),
				<Error<TestRuntime>>::AlreadyInitialized
			);
		})
	}

	#[test]
	fn init_fails_if_there_are_too_many_authorities_in_the_set() {
		run_test(|| {
			let genesis = test_header(0);
			let init_data = InitializationData {
				header: Box::new(genesis),
				authority_list: into_authority_set(
					(0..(MAX_BRIDGED_AUTHORITIES as u16) + 1).map(|x| Account(x)).collect(),
				),
				operating_mode: BasicOperatingMode::Normal,
			};

			assert_noop!(
				Pallet::<TestRuntime>::initialize(RuntimeOrigin::root(), init_data),
				Error::<TestRuntime>::TooManyAuthoritiesInSet,
			);
		});
	}

	#[test]
	fn parse_finalized_storage_accepts_valid_proof() {
		run_test(|| {
			let (state_root, storage_proof) = UnverifiedStorageProof::try_from_entries::<
				sp_core::Blake2Hasher,
			>(Default::default(), &[(b"key1".to_vec(), None)])
			.expect("UnverifiedStorageProof::try_from_entries() shouldn't fail in tests");

			let mut header = test_header(2);
			header.set_state_root(state_root);

			let hash = header.hash();
			<BestFinalized<TestRuntime>>::put(HeaderId(2, hash));
			<ImportedHeaders<TestRuntime>>::insert(hash, header.build());

			assert_ok!(Pallet::<TestRuntime>::verify_storage_proof(hash, storage_proof).map(|_| ()));
		});
	}

	#[test]
	fn storage_keys_computed_properly() {
		assert_eq!(
			PalletOperatingMode::<TestRuntime>::storage_value_final_key().to_vec(),
			bp_header_chain::storage_keys::pallet_operating_mode_key("Aleph").0,
		);

		assert_eq!(
			CurrentAuthoritySet::<TestRuntime>::storage_value_final_key().to_vec(),
			bp_header_chain::storage_keys::current_authority_set_key("Aleph").0,
		);

		assert_eq!(
			BestFinalized::<TestRuntime>::storage_value_final_key().to_vec(),
			bp_header_chain::storage_keys::best_finalized_key("Aleph").0,
		);
	}
}
