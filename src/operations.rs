// Copyright (c) 2023 Venkatesh Omkaram

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    aes::cipher::{
        crypto_common::generic_array::GenericArray,
        typenum::{UInt, UTerm, B0, B1, /*U32, U16*/ U12},
    },
    Aes256Gcm, //, Nonce, Key // Or `Aes128Gcm`
};
use byte_aes::Aes256Cryptor;
use file_shred::{shred, ShredConfig, Verbosity};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use lazy_static::lazy_static;
use rayon;
pub use std::sync::Mutex;
use std::{
    fmt::Write,
    fs,
    path::PathBuf,
    process,
    sync::{Arc, RwLock},
};
use walkdir::WalkDir;

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt;

use crate::{config::Shred, log::{log, LogLevel}};

/* What do the above imports do?
-----------------------
aes_gcm - Has the functions which helps to encrypt and decrypt the files for GCM mode
byte_aes - Has the functions which helps to encrypt and decrypt the files for ECB mode
lazy_static - A rust way to have Global variables
rayon - Helps to make the cipher operations multi-threaded
std - Has some standard core features to find Operation system, read and write files, find time, Atomic Reference Counter, process to forcefully exit the program execution
walkdir - Helps to walk through a given folder path
indicatif - Has some fancy ProgressBar and Spinners to print on the screen
file_shred - A basic file shred crate

Read the Cargo.toml and Attributions to see which versions and the Authors who made these crates
*/

// Specify the Global Variables. These variables are initialized using lazy_static macro and can be accessed anywhere in code
// Mutex is required to access these variables inside Rayon threads
lazy_static! {
    pub static ref ECB_32BYTE_KEY: RwLock<Vec<GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>>> =
        RwLock::new(Vec::new());
    pub static ref GCM_32BYTE_KEY: RwLock<Vec<GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>>> =
        RwLock::new(Vec::new());
    pub static ref DIR_LIST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    pub static ref FILE_LIST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    pub static ref FILES_SIZE_BYTES: Mutex<u64> = Mutex::new(0);
    pub static ref FAILED_COUNT: Mutex<u16> = Mutex::new(0);
    pub static ref SUCCESS_COUNT: Mutex<u16> = Mutex::new(0);
    pub static ref VERBOSE: RwLock<bool> = RwLock::new(false);
}

// A simple macro which prints only when verbose printing is specified using the -v program argument
macro_rules! logger {
    ($value: literal, $item: expr) => {
        if *VERBOSE.read().unwrap() {
            println!($value, $item);
        }
    };
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

impl Operation {
    pub fn to_str(&self) -> &str {
        match self {
            Operation::Encrypt => "Encrypt",
            Operation::Decrypt => "Decrypt",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// This function helps to Construct a ProgressBar for a given file count. But not to be used only when verbose printing is allowed.
// ProgressBar needs to be Arc<Mutex<>> because it will be shared among threads
fn progress_bar(file_count: u64) -> Option<Arc<Mutex<ProgressBar>>> {
    if !(*VERBOSE.read().unwrap()) {
        let pb = ProgressBar::new(file_count);

        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos} /{percent}% files completed ({eta_precise})")
                .unwrap()
                .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
                .progress_chars("#>-"));
        return Some(Arc::new(Mutex::new(pb)));
    }
    None
}

// Validates whether there are any Illegal source dir path is provided
// Validates whether any encrypted files are provided when the operation the user choose is to Encrypt
pub fn pre_validate_source(source_dir: &PathBuf, operation: &Operation) {
    let illegal_locations = [
        "/", "/root", "/home", "/boot", "/usr", "/lib", "/lib64", "/lib32", "/libx32", "/mnt",
        "/dev", "/sys", "/run", "/bin", "/sbin", "/proc", "/media", "/var", "/etc", "/srv", "/opt",
        "C:", "c:",
    ];

    if illegal_locations.contains(&source_dir.to_str().unwrap())
        || illegal_locations.iter().any(|x| source_dir.starts_with(x))
    {
        log(
            LogLevel::ERROR,
            format!("Hey Human, Are you trying to pass a illegal source path? That's a BIG NO NO.")
                .as_str(),
        );
        println!(
            "\nHere is the list of paths your source directory path must never start with : \n{:?}",
            illegal_locations
        );

        process::exit(1); // Exit if an illegal path is observed.
    }

    // Validate if the Source path has any encrypted file while the operation chosen by the user is encrypt
    if let Operation::Encrypt = operation {
        println!("\n\nValidating if the source directory has any encrypted files");

        for entry in WalkDir::new(source_dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let f_name = entry.file_name().to_string_lossy();

            // Check for the .enom file extension in the file names. .enom is the encrypted files extension
            if f_name.ends_with(".enom") {
                let file_path: PathBuf = entry.into_path().as_path().to_owned();

                log(LogLevel::ERROR, format!("Yikes! Found an encrypted file => {:?}, and there could be several.\n\nPlease ensure you are not encrypting already encrypted files. Doing double encryption won't help", file_path).as_str());

                process::exit(1); // Exit the program execution forcefully
            }
        }
    }
}

/* Recursively walk through the path provided and list all the sub-directory names and push it to a collection
Gathers the directory names and file names under the path
The DIR_LIST will be used to create the target directories
The FILE_LIST will be used know which files to Encrypt or Decrypt
FILE_SIZE_BYTES totals each file size
*/
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
                    if cfg!(unix) {
                        #[cfg(target_os = "linux")]
                        {
                            *FILES_SIZE_BYTES.lock().unwrap() +=
                                entry.path().metadata().unwrap().size();
                        }
                    } else if cfg!(windows) {
                        #[cfg(target_os = "windows")]
                        {
                            *FILES_SIZE_BYTES.lock().unwrap() +=
                                entry.path().metadata().unwrap().file_size();
                        }
                    }
                }
            } // end of for loop
        }
    }
}

// Creates the target directory and sub-directories by operating on the Paths.
pub fn create_dirs(paths: Vec<PathBuf>, source_dir_name: &str, target_dir_name: &str) {
    for parent in paths {
        let destination = parent
            .to_owned()
            .as_mut_os_str()
            .to_str()
            .unwrap()
            .replace(source_dir_name, target_dir_name);

        logger!("Directory created => {:?}", destination);

        let _ = fs::create_dir_all(destination);
    }
}

struct PbGroup {
    inner: Arc<Mutex<ProgressBar>>,
    bool: bool,
    increment: Arc<Mutex<u64>>,
}

// Construct a ProgressBar. ProgressBar is only available when verbose printing is not chosen. Hence it can come as None.
// When PB is not constructed, mark the pb_bool as false. PB increment counter starting value is 1
// This function expects a Closure logic for encrypt and decrypt operations
fn cipher_init<F>(file_list: &Vec<PathBuf>, thread_count: usize, f: F)
where
    F: Fn(Vec<u8>, PbGroup, Arc<RwLock<&PathBuf>>) + std::marker::Send + Copy + std::marker::Sync,
{
    let (pb, pb_bool, pb_increment): (Arc<Mutex<ProgressBar>>, bool, Arc<Mutex<u64>>) =
        match progress_bar(file_list.to_owned().capacity() as u64) {
            Some(pb) => (pb, true, Arc::new(Mutex::new(1))),
            None => (
                Arc::new(Mutex::new(ProgressBar::new(0))),
                false,
                Arc::new(Mutex::new(1)),
            ), // I hate this line. Unavoidable with my current knowledge.
        };
    // Construct a ThreadPool using Rayon
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();

    // For each element in file_list create a new thread and run it inside the thread scope
    // Rayon only allows certain number of threads to be created and executed in parallel based on the thread_count specified.
    pool.install(|| {
        rayon::scope(|s| {
            for file in file_list {
                let pb = PbGroup {
                    inner: pb.clone(),
                    increment: pb_increment.clone(),
                    bool: pb_bool,
                };

                let file = Arc::new(RwLock::new(file));

                // Spawn the threads here
                s.spawn(move |_| {
                    if let Ok(file_data) = fs::read(*file.clone().read().unwrap()) {
                        f(file_data, pb, file); // Closure call
                    }
                });
            }
        });
    });
}

/* Encrypts the files in the file_list in parallel based on the thread_count and Mode. Places the files the target directory
by replacing the source_dir_name with the target_dir_name.
Delete the source directory if the delete_src is true.
*/
pub fn encrypt_files(
    file_list: Vec<PathBuf>,
    thread_count: usize,
    source_dir_name: &str,
    target_dir_name: &str,
    mode: Mode,
    delete_src: bool,
    shred_options: &Option<Shred>
) {


    cipher_init(
        &file_list,
        thread_count,
        |file_data: Vec<u8>, pb: PbGroup, file: Arc<RwLock<&PathBuf>>| {
            match mode {
                Mode::ECB => {
                    //Create Aes256Cryptor Object
                    let encrypt_obj = Aes256Cryptor::new({
                        let mut key = [0u8; 32];
                        key.copy_from_slice(ECB_32BYTE_KEY.read().unwrap()[0].as_slice());
                        key
                    });

                    // Call the encrypt method on the Aes256Cryptor Object
                    let encrypted_bytes = encrypt_obj.encrypt(file_data); // vec<u8>

                    let new_file_name = file
                        .clone()
                        .read()
                        .unwrap()
                        .as_os_str()
                        .to_str()
                        .expect("Found a bad file")
                        .replace(source_dir_name, target_dir_name)
                        .to_string()
                        + ".enom";

                    logger!("Encrypted file :: {}", new_file_name);

                    // Write the encrypted bytes to new_file_name
                    let _ = fs::write(new_file_name, encrypted_bytes);

                    match &shred_options {
                        Some(o) => match o {
                            Shred::Shred(so) => {
                                if let Err(e) = shred(&ShredConfig::non_interactive(
                                    vec![&*file.clone().read().unwrap()],
                                    Verbosity::Quiet,
                                    false,
                                    so.random_iterations,
                                    so.rename_times,    
                                )) {
                                    logger!("Failed to shred the file :: {}", e);
                                }
                            },
                        },
                        None => {
                            // Delete the source file if delete_src is true. Note: This is not a safe delete. The file count still exist and it is possible to retrieve
                            if delete_src {
                                if let Err(e) = fs::remove_file(*file.clone().read().unwrap()) {
                                    logger!("Failed to delete the file :: {}", e);
                                }
                            }
                        },
                    };

                    // Increment the ProgressBar if pb_bool is true. Happens when verbose printing is not chosen
                    if pb.bool {
                        pb.inner
                            .lock()
                            .unwrap()
                            .set_position(*pb.increment.lock().unwrap());
                        *pb.increment.lock().unwrap() += 1;
                    }
                }

                Mode::GCM => {
                    // Extract the 32 byte key from the Vec and construct a Aes256Gcm object
                    let cipher: aes_gcm::AesGcm<aes_gcm::aes::Aes256, _, _> =
                        Aes256Gcm::new(&GCM_32BYTE_KEY.read().unwrap().as_slice()[0]);

                    // Generate a random 12 byte Nonce
                    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

                    // Call the encrypt method on the Aes256Gcm object and see if was successful
                    match cipher.encrypt(&nonce, file_data.as_ref()) {
                        Ok(encrypted_bytes) => {
                            // Success
                            let new_file_name = file
                                .clone()
                                .read()
                                .unwrap()
                                .as_os_str()
                                .to_str()
                                .expect("Found a bad file")
                                .replace(source_dir_name, target_dir_name)
                                .to_string()
                                + ".enom";

                            logger!("Encrypted file :: {}", new_file_name);

                            // Concat the encrypted_bytes and Nonce and Write it to new_file_name
                            let _ = fs::write(
                                new_file_name,
                                [encrypted_bytes, nonce.to_vec()].concat(),
                            );

                            *SUCCESS_COUNT.lock().unwrap() += 1;

                            match &shred_options {
                                Some(o) => match o {
                                    Shred::Shred(so) => {
                                        if let Err(e) = shred(&ShredConfig::non_interactive(
                                            vec![&*file.clone().read().unwrap()],
                                            Verbosity::Quiet,
                                            false,
                                            so.random_iterations,
                                            so.rename_times,    
                                        )) {
                                            logger!("Failed to shred the file :: {}", e);
                                        }
                                    },
                                },
                                None => {
                                    // Delete the source file if delete_src is true.
                                    if delete_src {
                                        if let Err(e) = fs::remove_file(*file.clone().read().unwrap()) {
                                            logger!("Failed to delete the file :: {}", e);
                                        }
                                    }
                                },
                            };

                            // Increment the ProgressBar
                            if pb.bool {
                                pb.inner
                                    .lock()
                                    .unwrap()
                                    .set_position(*pb.increment.lock().unwrap());
                                *pb.increment.lock().unwrap() += 1;
                            }
                        }
                        Err(_) => {
                            // Increment the failed count by 1 since the encryption failed.
                            *FAILED_COUNT.lock().unwrap() += 1;
                        }
                    } // vec<u8>
                }
            };
        },
    );
}

/* Decrypts the files in the file_list in parallel based on the thread_count and Mode. Places the files the target directory
by replacing the source_dir_name with the target_dir_name.
Delete the source directory if the delete_src is true.
*/
pub fn decrypt_files(
    file_list: Vec<PathBuf>,
    thread_count: usize,
    source_dir_name: &str,
    target_dir_name: &str,
    mode: Mode,
    delete_src: bool,
    shred_options: &Option<Shred>
) {
    cipher_init(
        &file_list,
        thread_count,
        |file_data: Vec<u8>, pb: PbGroup, file: Arc<RwLock<&PathBuf>>| {
            if let Mode::GCM = mode {
                let mut file_data: Vec<u8> = file_data;

                //let nonce = file_data.clone().into_iter().rev().take(12).rev().collect::<Vec<u8>>();
                // Onc we have file_data to be decrypted we need to extract the Nonce which we used to Encrypt.
                // The None is part of the file. It is the last 12 bytes in the encrypted file. We need to know where to Split
                // saturating_sub helps to find the position at which the split needs to happen which varies based on the file_data length.
                let final_length = file_data.len().saturating_sub(12);

                // Splits at the final_length. This length is the end of the actual file content and the start of the Nonce. It then returns the Nonce in a new Vec<u8>
                let nonce = file_data.split_off(final_length);

                let cipher: aes_gcm::AesGcm<aes_gcm::aes::Aes256, _, _> =
                    Aes256Gcm::new(&GCM_32BYTE_KEY.read().unwrap().as_slice()[0]);
                //let nonce: GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>> = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

                // We need the Nonce to be of type GenericArray to be used by the decrypt function
                let nonce = GenericArray::<u8, U12>::from_slice(nonce.as_ref());

                // File is decrypted here
                match cipher.decrypt(nonce, file_data.as_ref()) {
                    Ok(res) => {
                        let new_file_name = file
                            .clone()
                            .read()
                            .unwrap()
                            .as_os_str()
                            .to_str()
                            .unwrap()
                            .replace(source_dir_name, target_dir_name)
                            .replace(".enom", "")
                            .to_string();

                        logger!("Decrypted file :: {}", new_file_name);

                        let _ = fs::write(new_file_name, res);

                        *SUCCESS_COUNT.lock().unwrap() += 1;

                        match &shred_options {
                            Some(o) => match o {
                                Shred::Shred(so) => {
                                    if let Err(e) = shred(&ShredConfig::non_interactive(
                                        vec![&*file.clone().read().unwrap()],
                                        Verbosity::Quiet,
                                        false,
                                        so.random_iterations,
                                        so.rename_times,    
                                    )) {
                                        logger!("Failed to shred the file :: {}", e);
                                    }
                                },
                            },
                            None => {
                                // Delete the source file if delete_src is true. Note: This is not a safe delete. The file count still exist and it is possible to retrieve
                                if delete_src {
                                    if let Err(e) = fs::remove_file(*file.clone().read().unwrap()) {
                                        logger!("Failed to delete the file :: {}", e);
                                    }
                                }
                            },
                        };

                        if pb.bool {
                            pb.inner
                                .lock()
                                .unwrap()
                                .set_position(*pb.increment.lock().unwrap());
                            *pb.increment.lock().unwrap() += 1;
                        }
                    }
                    Err(_) => {
                        *FAILED_COUNT.lock().unwrap() += 1;
                    }
                }
            } else {
                //Create Aes256Cryptor Object
                let decrypt_obj = Aes256Cryptor::new({
                    let mut key = [0u8; 32];
                    key.copy_from_slice(ECB_32BYTE_KEY.read().unwrap()[0].as_slice());
                    key
                });

                let decrypted_result = decrypt_obj.decrypt(file_data);

                if let Ok(decrypted_bytes) = decrypted_result {
                    let new_file_name = file
                        .clone()
                        .read()
                        .unwrap()
                        .as_os_str()
                        .to_str()
                        .unwrap()
                        .replace(source_dir_name, target_dir_name)
                        .replace(".enom", "")
                        .to_string();

                    logger!("Decrypted file :: {}", new_file_name);

                    let _ = fs::write(new_file_name, decrypted_bytes);

                    match &shred_options {
                        Some(o) => match o {
                            Shred::Shred(so) => {
                                if let Err(e) = shred(&ShredConfig::non_interactive(
                                    vec![&*file.clone().read().unwrap()],
                                    Verbosity::Quiet,
                                    false,
                                    so.random_iterations,
                                    so.rename_times,    
                                )) {
                                    logger!("Failed to shred the file :: {}", e);
                                }
                            },
                        },
                        None => {
                            // Delete the source file if delete_src is true. Note: This is not a safe delete. The file count still exist and it is possible to retrieve
                            if delete_src {
                                if let Err(e) = fs::remove_file(*file.clone().read().unwrap()) {
                                    logger!("Failed to delete the file :: {}", e);
                                }
                            }
                        },
                    };

                    if pb.bool {
                        pb.inner
                            .lock()
                            .unwrap()
                            .set_position(*pb.increment.lock().unwrap());
                        *pb.increment.lock().unwrap() += 1;
                    }
                }
            };
        },
    );
}
