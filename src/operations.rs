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
use std::{fmt::Write, fs, path::PathBuf, process, sync::Arc, time::Duration};
use walkdir::WalkDir;
use std::env;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};

lazy_static! {
    pub static ref ECB_32BYTE_KEY: Mutex<String> = Mutex::new(String::new());
    pub static ref GCM_32BYTE_KEY: Mutex<Vec<GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>>> =
        Mutex::new(Vec::new());
    pub static ref DIR_LIST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    pub static ref FILE_LIST: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
    pub static ref FAILED_COUNT: Mutex<u16> = Mutex::new(0);
    pub static ref SUCCESS_COUNT: Mutex<u16> = Mutex::new(0);
    pub static ref VERBOSE: Mutex<bool> = Mutex::new(false);
}

macro_rules! logger {
    ($value: literal, $item: expr) => {
        if *VERBOSE.lock().unwrap() {
            println!($value, $item);}
    
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

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn progress_bar(file_count: u64) -> Option<ProgressBar> {
    if !(*VERBOSE.lock().unwrap()) {
        let pb = ProgressBar::new(file_count);

        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos} /{percent}% files completed ({eta_precise})")
            .unwrap()
            .with_key("eta", |state: &ProgressState, w: &mut dyn Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap())
            .progress_chars("#>-"));
        return Some(pb)
    }
    None
}


pub fn pre_validate_source(source_dir: &PathBuf, operation: &Operation) {
    let illegal_locations = 
        ["/", "/root", "/home", "/boot", "/usr", "/lib", "/lib64", "/lib32", 
        "/libx32", "/mnt", "/dev", "/sys", "/run", "/bin", "/sbin", "/proc", 
        "/media", "/var", "/etc", "/srv", "/opt", "C:", "c:"];

    if illegal_locations.contains(&source_dir.to_str().unwrap()) || illegal_locations.iter().any(|x| source_dir.starts_with(x)){
        println!("\nHey Human, Are you trying to pass a illegal source path? That's a BIG NO NO.");
        println!("\nHere is the list of paths your source directory path must never start with : {:?}", illegal_locations);

        process::exit(1);
    }

    if let Operation::Encrypt = operation{
        println!("\n\nValidating if the source directory has any encrypted files");
    for entry in WalkDir::new(source_dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok()) {
            
            let f_name = entry.file_name().to_string_lossy();

            if f_name.ends_with(".enom") {
                let file_path: PathBuf = entry.into_path().as_path().to_owned();
                println!("\nYikes! Found an encrypted file => {:?}, and there could be several. 
Please ensure you are not providing already encrypted files. Doing double encryption won't help", file_path);
                process::exit(1);
            }
        } 
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
            } // end of for loop
        }
    }
}

pub fn find_password_file() -> Option<PathBuf> {

    let os_type = env::consts::OS;
    let target_dir = match os_type {
        "linux" => vec![".", "..", "../../", "/etc", "/root", "/home"],
        "windows" => vec!["C:/WINDOWS/SYSTEM32/config", "."],
        _ => vec!["."]
    };

    for i in target_dir {
        let file_list: Vec<Result<walkdir::DirEntry, walkdir::Error>> = WalkDir::new(i).into_iter().collect();
        println!("\nSearching this many files : {:?}. Please be patient", file_list.capacity());
        let bar = ProgressBar::new_spinner();
        for entry in WalkDir::new(i)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok()) {
            
            bar.enable_steady_tick(Duration::from_millis(100));

            let f_name = entry.file_name().to_string_lossy();

            if f_name.ends_with(".omk") {
                println!("\nFound this => {:?}", entry.clone().into_path());
                let file_path: PathBuf = entry.into_path().as_path().to_owned();
                return Some(file_path);
            }
        } // end of inner for loop
    }
        return None;

    

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

        logger!("Directory created => {:?}", destination);
        
        let _ = fs::create_dir_all(destination);
    }
}

pub fn encrypt_files(
    file_list: Vec<PathBuf>,
    thread_count: usize,
    source_dir_name: &str,
    target_dir_name: &str,
    mode: Mode,
    delete_src: bool
) {
    let (pb, pb_bool): (ProgressBar, bool) = match progress_bar(file_list.capacity() as u64) {
        Some(pb) => (pb, true),
        None => (ProgressBar::new(0), false)
    };
    
    let pb_increment: Arc<Mutex<u64>> = Arc::new(Mutex::new(1));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();
    
    pool.install(|| {
        rayon::scope(|s| {
            for file in file_list {

                let pb = pb.clone(); // Unable to avoid these clone when there is Progress Bar use
                let pb_increment: Arc<Mutex<u64>> = pb_increment.clone();

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
                                    + ".enom";

                                logger!("Encrypted file :: {}", new_file_name);
                                
                                let _ = fs::write(new_file_name, encrypted_bytes);

                                if delete_src {
                                    if let Err(e) = fs::remove_file(file) {
                                        logger!("Failed to delete the file :: {}", e);
                                    }
                                }

                                if pb_bool {
                                    pb.set_position(*pb_increment.lock().unwrap());
                                    *pb_increment.lock().unwrap()+=1;
                                }
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
                                            + ".enom";
                                        
                                        logger!("Encrypted file :: {}", new_file_name);
                                        
                                        let _ = fs::write(
                                            new_file_name,
                                            [encrypted_bytes, nonce.to_vec()].concat(),
                                        );
                                        *SUCCESS_COUNT.lock().unwrap() += 1;

                                        if delete_src {
                                            if let Err(e) = fs::remove_file(file) {
                                                logger!("Failed to delete the file :: {}", e);
                                            }
                                        }
                                        
                                        if pb_bool {
                                            pb.set_position(*pb_increment.lock().unwrap());
                                            *pb_increment.lock().unwrap()+=1;
                                        }

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
    delete_src: bool
) {
    let (pb, pb_bool): (ProgressBar, bool) = match progress_bar(file_list.capacity() as u64) {
        Some(pb) => (pb, true),
        None => (ProgressBar::new(0), false)
    };
    
    let pb_increment: Arc<Mutex<u64>> = Arc::new(Mutex::new(1));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build()
        .unwrap();
    
    pool.install(|| {
        rayon::scope(|s| {
            for file in file_list {

                let pb = pb.clone(); // Unable to avoid these clone when there is Progress Bar use
                let pb_increment: Arc<Mutex<u64>> = pb_increment.clone();

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
                                        .replace(".enom", "")
                                        .to_string();

                                    logger!("Decrypted file :: {}", new_file_name);

                                    let _ = fs::write(new_file_name, res);

                                    *SUCCESS_COUNT.lock().unwrap() += 1;

                                    if delete_src {
                                        if let Err(e) = fs::remove_file(file) {
                                            logger!("Failed to delete the file :: {}", e);
                                        }
                                    }

                                    if pb_bool {
                                        pb.set_position(*pb_increment.lock().unwrap());
                                        *pb_increment.lock().unwrap()+=1;
                                    }

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
                                    .replace(".enom", "")
                                    .to_string();
                                
                                logger!("Decrypted file :: {}", new_file_name);
                                
                                let _ = fs::write(new_file_name, decrypted_bytes);

                                if delete_src {
                                    if let Err(e) = fs::remove_file(file) {
                                        logger!("Failed to delete the file :: {}", e);
                                    }
                                }

                                if pb_bool {
                                    pb.set_position(*pb_increment.lock().unwrap());
                                    *pb_increment.lock().unwrap()+=1;
                                }

                            }
                        };
                    }
                });
            }
        })
    })
}
