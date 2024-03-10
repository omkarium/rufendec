use aes_gcm::aes::cipher::{
    crypto_common::generic_array::GenericArray,
    typenum::{UInt, UTerm, B0, B1, /*U32, U16*/ U12},
};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, //, Nonce, Key // Or `Aes128Gcm`
};
use byte_aes::Aes256Cryptor;
use lazy_static::lazy_static;
use rayon;
pub use std::sync::Mutex;
use std::{fs, path::PathBuf};

lazy_static! {
    pub static ref ECB_32BYTE_KEY: Mutex<String> = Mutex::new(String::new());
    pub static ref GCM_32BYTE_KEY: Mutex<Vec<GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>>> =
        Mutex::new(Vec::new());
    pub static ref DIR_LIST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    pub static ref FILE_LIST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    pub static ref FAILED_COUNT: Mutex<u16> = Mutex::new(0);
    pub static ref SUCCESS_COUNT: Mutex<u16> = Mutex::new(0);
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

#[derive(clap::ValueEnum, Clone, Debug, Copy)]
pub enum Mode {
    ECB,
    GCM,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn recurse_dirs(item: &PathBuf) {
    if item.is_dir() {
        if let Ok(paths) = fs::read_dir(item) {

            for path in paths {
                let metadata = path.as_ref().unwrap().metadata();
                let entry = path.as_ref().unwrap();

                if metadata.unwrap().is_dir() {
                    let base_path = entry.path();
                    DIR_LIST.lock().unwrap().push(base_path);
                    recurse_dirs(&entry.path());
                } else {
                    FILE_LIST.lock().unwrap().push(entry.path());
                }

            }

        }
    }
}

pub fn create_dirs(
    paths: Vec<PathBuf>,
    operation: Operation,
    source_dir_name: &str,
    target_dir_name: &str,
) {
    for parent in paths {
        let destination = match operation {
            _ => parent
                .to_owned()
                .as_mut_os_str()
                .to_str()
                .unwrap()
                .replace(source_dir_name, target_dir_name),
        };

        println!("Directory created => {:?}", destination);
        
        let _ = fs::create_dir_all(destination);
    }
}

pub fn encrypt_files(
    file_list: Vec<PathBuf>,
    thread_count: usize,
    source_dir_name: &str,
    target_dir_name: &str,
    mode: Mode,
) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();
    pool.install(|| {
        rayon::scope(|s| {
            for file in file_list {
                s.spawn(move |_| {
                    if let Ok(file_data) = fs::read(file.clone()) {
                        match mode {
                            Mode::ECB => {
                                let encrypt_obj = Aes256Cryptor::try_from(
                                    &ECB_32BYTE_KEY
                                        .lock()
                                        .expect("Failed to get a lock on the password")
                                        as &str,
                                )
                                .unwrap();

                                let encrypted_bytes = encrypt_obj.encrypt(file_data); // vec<u8>
                                
                                let new_file_name = file
                                    .as_os_str()
                                    .to_str()
                                    .expect("Found a bad file")
                                    .replace(source_dir_name, target_dir_name)
                                    .to_string()
                                    + ".enc";

                                println!("Encrypted file :: {}", new_file_name);
                                
                                let _ = fs::write(new_file_name, encrypted_bytes);
                            }

                            Mode::GCM => {
                                let cipher: aes_gcm::AesGcm<aes_gcm::aes::Aes256, _, _> =
                                    Aes256Gcm::new(&GCM_32BYTE_KEY.lock().unwrap().as_slice()[0]);
                                
                                let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
                                
                                match cipher.encrypt(&nonce, file_data.as_ref()) {
                                    Ok(encrypted_bytes) => {
                                        let new_file_name = file
                                            .as_os_str()
                                            .to_str()
                                            .expect("Found a bad file")
                                            .replace(source_dir_name, target_dir_name)
                                            .to_string()
                                            + ".enc";
                                        
                                        println!("Encrypted file :: {}", new_file_name);
                                        
                                        let _ = fs::write(
                                            new_file_name,
                                            [encrypted_bytes, nonce.to_vec()].concat(),
                                        );
                                        *SUCCESS_COUNT.lock().unwrap() += 1;
                                    }
                                    Err(_) => {
                                        *FAILED_COUNT.lock().unwrap() += 1;
                                    }
                                } // vec<u8>
                            }
                        };
                    }
                });
            }
        })
    })
}

pub fn decrypt_files(
    file_list: Vec<PathBuf>,
    thread_count: usize,
    source_dir_name: &str,
    target_dir_name: &str,
    mode: Mode,
) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();
    pool.install(|| {
        rayon::scope(|s| {
            for file in file_list {
                s.spawn(move |_| {
                    if let Ok(file_data) = fs::read(file.clone()) {
                        if let Mode::GCM = mode {
                            let mut file_data: Vec<u8> = file_data;
                            
                            //let nonce = file_data.clone().into_iter().rev().take(12).rev().collect::<Vec<u8>>();
                            let final_length = file_data.len().saturating_sub(12);
                            
                            let nonce = file_data.split_off(final_length);
                            
                            let cipher: aes_gcm::AesGcm<aes_gcm::aes::Aes256, _, _> =
                                Aes256Gcm::new(&GCM_32BYTE_KEY.lock().unwrap().as_slice()[0]);
                            //let nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>> = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
                            
                            let nonce = GenericArray::<u8, U12>::from_slice(nonce.as_ref());
                            
                            match cipher.decrypt(nonce, file_data.as_ref()) {
                                Ok(res) => {
                                    let new_file_name = file
                                        .as_os_str()
                                        .to_str()
                                        .unwrap()
                                        .replace(source_dir_name, target_dir_name)
                                        .replace(".enc", "")
                                        .to_string();
                                    println!("Decrypted file :: {}", new_file_name);
                                    let _ = fs::write(new_file_name, res);
                                    *SUCCESS_COUNT.lock().unwrap() += 1;
                                }
                                Err(_) => {
                                    *FAILED_COUNT.lock().unwrap() += 1;
                                }
                            }

                        } else {
                            let decrypt_obj = Aes256Cryptor::try_from(
                                &ECB_32BYTE_KEY
                                    .lock()
                                    .expect("Failed to get a lock on the password")
                                    as &str,
                            )
                            .unwrap();

                            let decrypted_result = decrypt_obj.decrypt(file_data);
                            
                            if let Ok(decrypted_bytes) = decrypted_result {
                                let new_file_name = file
                                    .as_os_str()
                                    .to_str()
                                    .unwrap()
                                    .replace(source_dir_name, target_dir_name)
                                    .replace(".enc", "")
                                    .to_string();
                                
                                println!("Decrypted file :: {}", new_file_name);
                                
                                let _ = fs::write(new_file_name, decrypted_bytes);
                            }
                        };
                    }
                });
            }
        })
    })
}
