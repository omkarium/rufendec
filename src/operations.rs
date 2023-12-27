use byte_aes::Encryptor;
use byte_aes::Decryptor;
use std::{fs, path::PathBuf};
pub use std::sync::Mutex;
use rayon;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref MY_32BYTE_KEY: Mutex<String> =  Mutex::new(String::new());
    pub static ref DIR_LIST: Mutex<Vec<PathBuf>> =  Mutex::new(Vec::new());
    pub static ref FILE_LIST: Mutex<Vec<PathBuf>> =  Mutex::new(Vec::new());
}

#[derive(
    clap::ValueEnum, Clone, Debug
)]
pub enum Operation{
    Encrypt,
    Decrypt
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

pub fn create_dirs(paths: Vec<PathBuf>, operation: Operation, source_dir_name: &str, target_dir_name: &str) {
   for parent in paths {
       let destination = match operation {
           _ => parent.to_owned().as_mut_os_str().to_str().unwrap().replace(source_dir_name, target_dir_name),
       };
       println!("Directory created => {:?}", destination);
       let _ = fs::create_dir_all(destination);
   }
}

pub fn encrypt_files(file_list: Vec<PathBuf>, thread_count: usize, source_dir_name: &str, target_dir_name: &str) {
   let pool = rayon::ThreadPoolBuilder::new().num_threads(thread_count).build().unwrap();
   pool.install(|| {
       rayon::scope(|s| {
           for file in file_list {
               s.spawn(move |_| {
                   if let Ok(file_data)  = fs::read_to_string(file.clone()){
                       let mut encrypt_obj: Encryptor = Encryptor::from(file_data);
                       let encrypted_bytes: Vec<u8> = encrypt_obj.encrypt_with(&MY_32BYTE_KEY.lock().expect("Failed to get a lock on the password"));
           
                       let new_file_name = file.as_os_str().to_str().expect("Found a bad file").replace(source_dir_name, target_dir_name).to_string() + ".enc";
                       println!("Encrypted file :: {}", new_file_name);
                       let _ = fs::write(new_file_name, encrypted_bytes);
                   }
               });
           }
       })
   })
   
}

pub fn decrypt_files(file_list: Vec<PathBuf>, thread_count: usize, source_dir_name: &str, target_dir_name: &str) {
   let pool = rayon::ThreadPoolBuilder::new().num_threads(thread_count).build().unwrap();
   pool.install(|| {
       rayon::scope(|s| {
           for file in file_list {
               s.spawn(move |_| {
                   if let Ok(file_data)  = fs::read(file.clone()){
                       let mut decrypt_obj: Decryptor = Decryptor::from(file_data);
                       let decrypted_bytes: Vec<u8> = decrypt_obj.decrypt_with(&MY_32BYTE_KEY.lock().expect("Failed to get a lock on the password"));
                       let new_file_name = file.as_os_str().to_str().unwrap().replace(source_dir_name, target_dir_name).replace(".enc", "").to_string();
                       println!("Decrypted file :: {}", new_file_name);
                       let _ = fs::write(new_file_name, decrypted_bytes);
                   }
               });
           }
       })
   })
}
