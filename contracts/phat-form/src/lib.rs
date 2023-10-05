#![cfg_attr(not(feature = "std"), no_std, no_main)]
extern crate alloc;

use pink_extension as pink;
pub use phat_form::*;

#[pink::contract(env=PinkEnvironment)]
mod phat_form {
    use super::pink;
    use pink::chain_extension::signing as sig;
    use sig::SigType;
    use pink::PinkEnvironment;
    use alloc::{string::String, vec::Vec};
    use scale::{Decode, Encode};
    #[cfg(feature = "std")]
    use ink::storage::{traits::StorageLayout};
    use ink::storage::Mapping;

    pub type HackerId = u64;

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NoPermissions,
        AccountAlreadyAdded,
        MissingHackerId,
        EmptyHackerInfo,
    }

    /// Type alias for the contract's result type.
    pub type Result<T> = core::result::Result<T, Error>;

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, StorageLayout))]
    pub struct HackerInfo {
        first_name: String,
        last_name: String,
        street_address_1: String,
        street_address_2: Option<String>,
        city: String,
        state_region_province: String,
        country: String,
        po_box: Option<String>,
        email: String,
        discord: String,
        twitter: String,
    }

    #[ink(storage)]
    pub struct PhatForm {
        privkey: Vec<u8>,
        pubkey: Vec<u8>,
        admin: AccountId,
        whitelist: Vec<AccountId>,
        hackers: Mapping<HackerId, HackerInfo>,
        default_address: AccountId,
        next_hacker_id: HackerId,
    }

    impl PhatForm {
        /// Constructor to initialize your contract
        #[ink(constructor)]
        pub fn default() -> Self {
            let gen_privkey = sig::derive_sr25519_key(b"a spoon of salt");
            let gen_pubkey = sig::get_public_key(&gen_privkey, SigType::Sr25519);
            let mut whitelist_vec: Vec<AccountId> = Vec::new();
            whitelist_vec.push(Self::zero_address());
            Self {
                privkey: gen_privkey,
                pubkey: gen_pubkey,
                admin: Self::env().caller(),
                whitelist: whitelist_vec,
                hackers: Mapping::default(),
                default_address: Self::zero_address(),
                next_hacker_id: 1,
            }
        }

        #[ink(message)]
        pub fn add_hacker_info(&mut self, info: HackerInfo) -> Result<bool> {
            let caller = self.env().caller();
            if !self.whitelist.contains(&caller) {
                return Err(Error::NoPermissions);
            }
            let id = self.get_hacker_id_or_zero(caller);
            if id == 0 {
                return Err(Error::MissingHackerId);
            }
            self.hackers.insert(id, &info);

            Ok(true)
        }

        #[ink(message)]
        pub fn add_to_whitelist(&mut self, account: AccountId) -> Result<()> {
            if self.env().caller() != self.admin {
                return Err(Error::NoPermissions);
            }
            if self.whitelist.contains(&account) {
                return Err(Error::AccountAlreadyAdded)
            }

            let hacker_id = self.next_hacker_id;
            self.whitelist.insert(hacker_id as usize, account);
            self.next_hacker_id += 1;
            Ok(())
        }

        #[ink(message)]
        pub fn add_vec_to_whitelist(&mut self, accounts: Vec<AccountId>) -> Result<()> {
            if self.env().caller() != self.admin {
                return Err(Error::NoPermissions);
            }
            for account in accounts {
                if !self.whitelist.contains(&account) {
                    let hacker_id = self.next_hacker_id;
                    self.whitelist.insert(hacker_id as usize, account);
                    self.next_hacker_id += 1;
                }
            }

            Ok(())
        }

        #[ink(message)]
        pub fn get_all_hacker_info(&self) -> Result<Vec<HackerInfo>> {
            // Check if caller is admin
            if self.env().caller() != self.admin {
                return Err(Error::NoPermissions);
            }

            // Get all hacker information
            let mut all_hackers: Vec<HackerInfo> = Vec::new();
            for id in 0..self.next_hacker_id {
                if let Some(hacker_info) = self.hackers.get(id) {
                    all_hackers.push(hacker_info);
                };
            }
            if all_hackers.is_empty() {
                return Err(Error::EmptyHackerInfo);
            }
            Ok(all_hackers)
        }

        #[ink(message)]
        pub fn hacker_count(&self) -> u64 {
            self.next_hacker_id
        }

        fn get_hacker_id_or_zero(&self, account: AccountId) -> HackerId {
            let mut index = 0;
            for id in 0..self.next_hacker_id {
                let hacker_account = self.whitelist[id as usize];
                if account == hacker_account {
                    index = id;
                }
            }
            index
        }

        fn zero_address() -> AccountId {
            [0u8; 32].into()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn add_hacker_info_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let mut contract = PhatForm::default();
            let accounts = ink::env::test::default_accounts::<pink::PinkEnvironment>();
            let admin = AccountId::from([0x0; 32]);
            let john = accounts.bob;
            let jane = accounts.eve;
            // Add test account to whitelist
            assert_eq!(contract.add_to_whitelist(john), Ok(()));
            let info = HackerInfo {
                first_name: String::from("John"),
                last_name: String::from("Doe"),
                street_address_1: String::from("1111 Brickhouse Dr."),
                street_address_2: None,
                city: String::from("City"),
                state_region_province: String::from("State/Region/Province"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("john"),
                twitter: String::from("john")
            };
            ink::env::test::set_caller::<pink::PinkEnvironment>(john);
            // Current account can add hacker info
            assert!(contract.add_hacker_info(info).unwrap());
            ink::env::test::set_caller::<pink::PinkEnvironment>(jane);
            // Non-whitelisted account cannot add hacker info
            let non_whitelisted_info = HackerInfo {
                first_name: String::from("Jane"),
                last_name: String::from("Doe"),
                street_address_1: String::from("1111 Brickhouse Dr."),
                street_address_2: None,
                city: String::from("City"),
                state_region_province: String::from("State/Region/Province"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("jane"),
                twitter: String::from("jane")
            };
            assert_eq!(contract.add_hacker_info(non_whitelisted_info), Err(Error::NoPermissions));
        }

        #[ink::test]
        fn add_to_whitelist_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let mut contract = PhatForm::default();
            let accounts = ink::env::test::default_accounts::<pink::PinkEnvironment>();
            let account = accounts.alice;
            // Only the admin can add to the whitelist
            assert_eq!(contract.add_to_whitelist(account), Ok(()));
            assert!(contract.whitelist.contains(&account));
        }

        #[ink::test]
        fn get_all_hacker_info_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let mut contract = PhatForm::default();
            // Add test account to whitelist and add hacker info
            let accounts = ink::env::test::default_accounts::<pink::PinkEnvironment>();
            let admin = ink::env::account_id::<pink::PinkEnvironment>();
            let alice = accounts.alice;
            let john = accounts.bob;
            let jane = accounts.eve;
            assert_eq!(contract.add_to_whitelist(alice), Ok(()));
            assert_eq!(contract.add_to_whitelist(john), Ok(()));
            assert_eq!(contract.add_to_whitelist(jane), Ok(()));
            ink::env::test::set_caller::<pink::PinkEnvironment>(alice);
            let info = HackerInfo {
                first_name: String::from("FirstName"),
                last_name: String::from("LastName"),
                street_address_1: String::from("StreetAddress1"),
                street_address_2: Some(String::from("StreetAddress2")),
                city: String::from("City"),
                state_region_province: String::from("State"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("alice"),
                twitter: String::from("alice")
            };
            assert!(contract.add_hacker_info(info).unwrap());
            let info_john = HackerInfo {
                first_name: String::from("John"),
                last_name: String::from("Doe"),
                street_address_1: String::from("1111 Brickhouse Dr."),
                street_address_2: None,
                city: String::from("City"),
                state_region_province: String::from("State/Region/Province"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("john"),
                twitter: String::from("john")
            };
            ink::env::test::set_caller::<pink::PinkEnvironment>(john);
            // Current account can add hacker info
            assert!(contract.add_hacker_info(info_john).unwrap());
            ink::env::test::set_caller::<pink::PinkEnvironment>(jane);
            // Non-whitelisted account cannot add hacker info
            let info_jane = HackerInfo {
                first_name: String::from("Jane"),
                last_name: String::from("Doe"),
                street_address_1: String::from("1111 Brickhouse Dr."),
                street_address_2: None,
                city: String::from("City"),
                state_region_province: String::from("State/Region/Province"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("jane"),
                twitter: String::from("jane")
            };
            assert!(contract.add_hacker_info(info_jane).unwrap());

            ink::env::test::set_caller::<pink::PinkEnvironment>(admin);

            // Try to get all hacker info as an admin
            let all_hacker_info = contract.get_all_hacker_info();
            let all_unwrap_info = all_hacker_info.unwrap();
            assert!(!all_unwrap_info.is_empty());
            assert_eq!(all_unwrap_info.len(), 3);

            ink::env::test::set_caller::<pink::PinkEnvironment>(jane);
            // Non-admins cannot get all hacker info
            let non_admin_hacker_info = contract.get_all_hacker_info();
            assert_eq!(non_admin_hacker_info, Err(Error::NoPermissions));
        }

        #[ink::test]
        fn add_vec_to_whitelist_works() {
            pink_extension_runtime::mock_ext::mock_all_ext();
            let mut contract = PhatForm::default();
            // Add test account to whitelist and add hacker info
            let accounts = ink::env::test::default_accounts::<pink::PinkEnvironment>();
            let admin = ink::env::account_id::<pink::PinkEnvironment>();
            let alice = accounts.alice;
            let john = accounts.bob;
            let jane = accounts.eve;
            let account_vec: Vec<AccountId> = vec![alice, john, jane];
            assert_eq!(contract.add_vec_to_whitelist(account_vec), Ok(()));
            ink::env::test::set_caller::<pink::PinkEnvironment>(alice);
            let info = HackerInfo {
                first_name: String::from("FirstName"),
                last_name: String::from("LastName"),
                street_address_1: String::from("StreetAddress1"),
                street_address_2: Some(String::from("StreetAddress2")),
                city: String::from("City"),
                state_region_province: String::from("State"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("alice"),
                twitter: String::from("alice")
            };

            let info_john = HackerInfo {
                first_name: String::from("John"),
                last_name: String::from("Doe"),
                street_address_1: String::from("1111 Brickhouse Dr."),
                street_address_2: None,
                city: String::from("City"),
                state_region_province: String::from("State/Region/Province"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("john"),
                twitter: String::from("john")
            };

            let info_jane = HackerInfo {
                first_name: String::from("Jane"),
                last_name: String::from("Doe"),
                street_address_1: String::from("1111 Brickhouse Dr."),
                street_address_2: None,
                city: String::from("City"),
                state_region_province: String::from("State/Region/Province"),
                country: String::from("Country"),
                po_box: None,
                email: String::from("Email"),
                discord: String::from("jane"),
                twitter: String::from("jane")
            };
            assert!(contract.add_hacker_info(info).unwrap());
            ink::env::test::set_caller::<pink::PinkEnvironment>(john);
            // Current account can add hacker info
            assert!(contract.add_hacker_info(info_john).unwrap());
            ink::env::test::set_caller::<pink::PinkEnvironment>(jane);
            // Non-whitelisted account cannot add hacker info

            assert!(contract.add_hacker_info(info_jane).unwrap());

            ink::env::test::set_caller::<pink::PinkEnvironment>(admin);

            // Try to get all hacker info as an admin
            let all_hacker_info = contract.get_all_hacker_info();
            let all_unwrap_info = all_hacker_info.unwrap();
            assert!(!all_unwrap_info.is_empty());
            assert_eq!(all_unwrap_info.len(), 3);

            ink::env::test::set_caller::<pink::PinkEnvironment>(jane);
            // Non-admins cannot get all hacker info
            let non_admin_hacker_info = contract.get_all_hacker_info();
            assert_eq!(non_admin_hacker_info, Err(Error::NoPermissions));
        }
    }
}
