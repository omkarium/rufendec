//! # Rufendec
//! 
//! #### Developer: Omkarium
//! 
//! Rufendec aka (Rust File Encryptor-Decryptor) is a CLI utility tool which helps you to do AES-256 Encryption and Decryption on specified directories/folders
//! and retain the complete directory structure of the source directory files you provide into the target directory.
//! 
//! ## How to Use
//! This is a binary crate, so its obvious that you need to use this as an executable. 
//! First have cargo install and then run `cargo install rufendec`
//! Next, go to the location of the binary and run the executable
//! 
//! ### Example
//! If you run cargo run -- --help or ./rufendec --help. You will get this response
//! ```
//! Rufendec aka (Rust File Encryptor-Decryptor) is a CLI utility tool which helps you to do AES-256 Encryption and Decryption on specified directories/folders and retain the complete directory structure of the source directory files you provide into the target directory.
//! 
//! Usage: rufendec [OPTIONS] --password-file <PASSWORD_FILE> --operation <OPERATION> --mode <MODE> <SOURCE_DIR> <TARGET_DIR>
//!
//! Arguments:
//! <SOURCE_DIR>  Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
//! <TARGET_DIR>  Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go)
//!
//! Options:
//! -p, --password-file <PASSWORD_FILE>    Enter the Filename containing your password (and the "salt" in the 2nd line if you choose gcm) here. This is used to either Encrypt or Decrypt the Source Dir files
//! -o, --operation <OPERATION>            Enter the Operation you want to perform on the Source Dir using the password you provided [possible values: encrypt, decrypt]
//! -t, --threads <THREADS>                Threads to speed up the execution [default: 8]
//! -m, --mode <MODE>                      Provide the mode of Encryption here [possible values: ecb, gcm]
//! -i, --iterations <ITERATIONS>          Iterations --mode=gcm [default: 60000]
//! -h, --help                             Print help
//! -V, --version                          Print version
//! ```
//! for example, say if you want to encrypt all the files in directory say `./source-dir` using a password (example password: **Thisi/MyKeyT0Encrypt**) which is maintained in a passwordfile, and create a target directory say `./target-dir` which will hold the encrypted files
//! by **retaining the complete folder structure of the source-dir and its sub-directories in the target-dir**, then you can run the command like this
//! ```
//! cargo run ../source-dir ../target-dir --password-file=../passwordfile --operation=encrypt --mode=ecb
//! ```
//! or
//! ```
//! ./rufendec ./source-dir ./target-dir --password-file=./passwordfile --operation=encrypt --mode=ecb
//! ```
//! Next, say you deleted the source-dir after encryption, and now you want the decrypted files and their respective directory structure back.
//! To decrypt the encrypted files inside the target-dir you currently have, just run the below command. Once finished, your original files will be back in your source-dir
//! ```
//! cargo run ../target-dir ../source-dir --password-file=../passwordfile --operation=decrypt --mode=ecb
//! ```
//! or
//! ```
//! ./rufendec ./target-dir ./source-dir --password-file=./passwordfile --operation=decrypt --mode=ecb
//! ```
//! In the above examples, the names `source-dir` and `target-dir` are arbitrary. You can use any names to your source and target directories.
//! 
//! *Also, when you choose GCM mode, you have to pass a salt in the 2nd line after specifying the password in th 1st line. But if you go for ECB mode, you dont need to specify a salt.
//! In either case, the password and salt can be of any arbitrary length because the key generation in the program is happening via PBKDF2.*
//!
//! Example context inside a ./passwordfile
//! ```
//! Som3RandPa$$wdOfAnyLength
//! SomethingSaltIGiveOfAnyLength
//! ```
mod operations;

use clap::Parser;
use std::{time::Instant, path::PathBuf, fs};
use crate::operations::{
    ECB_32BYTE_KEY, GCM_32BYTE_KEY, DIR_LIST, FILE_LIST, FAILED_COUNT, SUCCESS_COUNT,
    create_dirs, decrypt_files, 
    encrypt_files, recurse_dirs
};
use crate::operations::{Operation, Mode};

use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key};


#[derive(Parser)]
#[command(author="@github.com/omkarium", version, about, long_about = None)]
struct Args {
    /// Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
    source_dir: String,
    /// Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go)
    target_dir: String,
    /// Enter the Filename containing your password (and the 'salt' in the 2nd line if you choose gcm) here. This is used to either Encrypt or Decrypt the Source Dir files
    #[arg(short, long)]
    password_file: String,
    /// Enter the Operation you want to perform on the Source Dir using the password you provided
    #[clap(short, long, value_enum)]    
    operation: Operation,
    /// Threads to speed up the execution [default: 8]
    #[clap(short, long, default_value_t = 8)]
    threads: usize,
    /// Provide the mode of Encryption here
    #[clap(short, long, value_enum)]    
    mode: Mode,
    /// Iterations --mode=gcm [default: 60000]
    #[clap(short, long, default_value_t = 60_000)]
    iterations: u32,
}

fn main() {
    let args = Args::parse();
    match args.mode {
        Mode::ECB => {
            *ECB_32BYTE_KEY.lock().unwrap() = fs::read_to_string(args.password_file).expect("The password is not found in the passwordfile").trim().to_owned();
            if ECB_32BYTE_KEY.lock().unwrap().len() != 32 {
                panic!("The key specified in the password file is not of 32 bytes. Did you miss characters? or did you specify a 2nd line by accident?");
            }
        },
        Mode::GCM => {
            let file = fs::read_to_string(args.password_file).expect("The password is not found in the passwordfile");
            let mut lines = file.trim().lines();
            let password = lines.next().expect("Password is expected").as_bytes();
            let salt = lines.next().expect("Salt is expected in the password-file").as_bytes();
            //let salt = SaltString::generate(&mut OsRng);
            let key = pbkdf2_hmac_array::<Sha256, 32>(password, salt, args.iterations);
            let key_gen = Key::<Aes256Gcm>::from_slice(&key);
            GCM_32BYTE_KEY.lock().unwrap().push(key_gen.to_owned())

        }
    }
    let path = PathBuf::from(args.source_dir.clone());
    DIR_LIST.lock().unwrap().push(path.clone());
    recurse_dirs(&path);
    println!("\n################### BEGIN #########################");
    println!("The source directory you provided : {:?}", args.source_dir);
    println!("The target director you provided : {:?}", args.target_dir);
    println!("This number of directories will be created in the target directory : {}", DIR_LIST.lock().unwrap().to_vec().capacity());
    println!("This number of files will be created in the target directory: {}", FILE_LIST.lock().unwrap().to_vec().capacity());
    println!("Total threads about to be used : {}", args.threads);
    println!("Operation and the Mode you are about to perform on the source directory : {:?} {:?}", args.operation, args.mode);

    println!("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    use std::io::{stdin,stdout,Write};
    let mut s=String::new();
    println!("Alert!!! Most file encryption softwares are destructive in nature. You MUST know what you are doing.
         Before you encrypt files, kindly take this as a strict caution and don't forget to take a backup of your souce files.
         
         =======================================
         Two important points before you proceed
         =======================================

         1. Makesure you are not decrypting a source folder which is not encrypted. 
            If done so, your source files will get corrupted.
            This program will not be able to pre-validate whether the files you have provided as either encrypted or decrypted. 

         2. This program refuses to encrypt those kind of files which are not utf-8 compatible, for example binary files.
            It will either create or skip such files, but ensure you don't try to encrypt anything as such.

         3. If you encrypted with --mode=gcm, and you tried to decrypt with --mode=ecb, 
            then the program generates the target files but filled with junk.
         
         Ensure you provide the correct files for the operation you choose");
    println!("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    print!("Please type Y for yes, and N for no : ");
    let _=stdout().flush();
    stdin().read_line(&mut s).expect("You entered incorrect response");
    if let Some('\n')=s.chars().next_back() {
        s.pop();
    }
    if let Some('\r')=s.chars().next_back() {
        s.pop();
    }
    println!("You typed: {}",s);

    if s == "Y" {
        let start_time = Instant::now();
        match args.operation {
            Operation::Encrypt => {
                create_dirs(DIR_LIST.lock().unwrap().to_vec(), Operation::Encrypt, args.source_dir.as_str(), args.target_dir.as_str());
                encrypt_files(FILE_LIST.lock().unwrap().to_vec(), args.threads, args.source_dir.as_str(), args.target_dir.as_str(), args.mode);
            },
            Operation::Decrypt => {
                create_dirs(DIR_LIST.lock().unwrap().to_vec(), Operation::Decrypt, args.source_dir.as_str(), args.target_dir.as_str());
                decrypt_files(FILE_LIST.lock().unwrap().to_vec(), args.threads, args.source_dir.as_str(), args.target_dir.as_str(), args.mode);
            }
        }
        let elapsed = Some(start_time.elapsed());
        println!("\n============Results==============\n");
        println!("Time taken to finish the {:?}, Operation: {:?}", args.operation, elapsed.unwrap());

        if args.mode.to_string() == "GCM" {
            println!("\nTotal Success count: {}", SUCCESS_COUNT.lock().unwrap());
            println!("Total failure count: {}", FAILED_COUNT.lock().unwrap());
        }

        if *FAILED_COUNT.lock().unwrap() > 0 {
            println!("\nLooks like we got some failures 😰. Please check if the you provided the correct password (and the salt in case you are using GCM mode)");
        } else {
            println!("\nWe are done. Enjoy hacker!!! 😎");
        }
        println!("\n=================================\n");

    } else {
        println!("\nPhew... You QUIT! Guess you really know what you are doing. Good choice.\n");

    }
}
