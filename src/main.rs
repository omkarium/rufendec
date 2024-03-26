//! # Rufendec
//! 
//! #### Developer: Venkatesh Omkaram
//! 
//! Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool designed for AES-256 encryption and decryption. 
//! This tool simplifies the process of securing  the contents of a user specified source directory. Operating in ECB/GCM modes, Rufendec maintains the original file names and sub-directory structure in the target directory. Explore the simplicity of Rust for robust encryption and decryption tasks with Rufendec.
//! 
//! ## How to Use
//! This is a binary crate, so its obvious that you need to use this as an executable. 
//! First have cargo install and then run `cargo install rufendec`
//! Next, go to the location of the binary and run the executable
//! 
//! ### Example
//! If you run cargo run -- --help or ./rufendec --help. You will get this response
//! ```
//! Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool designed for AES-256 encryption and decryption. 
//! This tool simplifies the process of securing  the contents of a user specified source directory. Operating in ECB/GCM modes, Rufendec maintains the original file names and sub-directory structure in the target directory. 
//! Explore the simplicity of Rust for robust encryption and decryption tasks with Rufendec.

//! Usage: rufendec [OPTIONS] --operation <OPERATION> <SOURCE_DIR> [TARGET_DIR]

//! Arguments:
//! <SOURCE_DIR>  Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
//! [TARGET_DIR]  Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go). But if you do not provide this, the target files will be placed in the Source Dir. To delete the source files make sure you pass option -d


//! Options:
//! -d, --delete-src                       Pass this option to delete the source files in the Source Dir
//! -p, --password-file <PASSWORD_FILE>    Enter the password file with an extension ".omk". The first line in the file must have the password, and If you choose mode=gcm then ensure to pass the "Salt" in the 2nd line [default: ]
//! -o, --operation <OPERATION>            Enter the Operation you want to perform on the Source Dir [possible values: encrypt, decrypt]
//! -t, --threads <THREADS>                Threads to speed up the execution [default: 8]
//! -m, --mode <MODE>                      Provide the mode of Encryption here [default: gcm] [possible values: ecb, gcm]
//! -i, --iterations <ITERATIONS>          Iterations --mode=gcm [default: 60000]
//! -v, --verbose                          Print verbose output
//! -h, --help                             Print help
//! -V, --version                          Print version
//! ```
//! for example, say if you want to encrypt all the files in directory say `./source-dir` using a password (example password: **Thisi/MyKeyT0Encrypt**) which is maintained in a passwordfile, and create a target directory say `./target-dir` which will hold the encrypted files
//! by **retaining the complete folder structure of the source-dir and its sub-directories in the target-dir**, then you can run the command like this
//! ```
//! cargo run ../source-dir ../target-dir --password-file=../passwordfile --operation=encrypt --mode=gcm
//! ```
//! 
//! Next, say you deleted the source-dir after encryption, and now you want the decrypted files and their respective directory structure back.
//! To decrypt the encrypted files inside the target-dir you currently have, just run the below command. Once finished, your original files will be back in your source-dir
//! ```
//! cargo run ../target-dir ../source-dir --password-file=../passwordfile --operation=decrypt --mode=gcm
//! ```
//! In the above examples, the names `source-dir` and `target-dir` are arbitrary. You can use any names to your source and target directories.
//! 
//! *Also, when you choose GCM mode, you have to pass a salt in the 2nd line after specifying the password in th 1st line. But if you go for ECB mode, you don't need to specify a salt.
//! In either case, the password and salt can be of any arbitrary length because the key generation in the program is happening via PBKDF2.*
//!
//! Example context inside a ./passwordfile
//! ```
//! Som3RandPa$$wdOfAnyLength
//! SomethingSaltIGiveOfAnyLength
//! ```
mod operations;

use clap::Parser;
use std::{borrow::Cow, fs, io::{stdin,stdout,Write}, path::PathBuf, time::Instant};
use crate::operations::{
    create_dirs, decrypt_files, encrypt_files, find_password_file, pre_validate_source, recurse_dirs, DIR_LIST, ECB_32BYTE_KEY, FAILED_COUNT, FILE_LIST, GCM_32BYTE_KEY, SUCCESS_COUNT, VERBOSE
};
use crate::operations::{Operation, Mode};
use rpassword::prompt_password;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key};
use std::env;

#[derive(Parser)]
#[command(author="@github.com/omkarium", version, about, long_about = None)]
struct Args {
    /// Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
    source_dir: String,
    /// Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go).
    /// But if you do not provide this, the target files will be placed in the Source Dir. 
    /// To delete the source files make sure you pass option -d
    target_dir: Option<String>,
    /// Pass this option to delete the source files in the Source Dir
    #[clap(short, long, default_value_t = false)]
    delete_src: bool, 
    /// Enter the password file with an extension ".omk". The first line in the file must have the password, and If you choose mode=gcm then ensure to pass the "Salt" in the 2nd line
    #[arg(short, long, default_value_t = String::new())]
    password_file: String,
    /// Enter the Operation you want to perform on the Source Dir
    #[clap(short, long, value_enum)]    
    operation: Operation,
    /// Threads to speed up the execution
    #[clap(short, long, default_value_t = 8)]
    threads: usize,
    /// Provide the mode of Encryption here
    #[clap(short, long, value_enum, default_value_t = Mode::GCM)]    
    mode: Mode,
    /// Iterations for PBKDF2
    #[clap(short, long, default_value_t = 60_000)]
    iterations: u32,
    /// Print verbose output
    #[clap(short, long, default_value_t = false)]
    verbose: bool    

}

fn password_prompt() -> (String, String) {
    (prompt_password("Enter the Password: ").expect("You entered a bad password").trim().to_owned(),
    prompt_password("\nEnter the Salt: ").expect("You entered a bad salt").trim().to_owned())
}

fn confirmation() -> String {
    let mut confirmation: String=String::new();
    print!("\nPlease type Y for yes, and N for no : ");

    let _=stdout().flush();

    stdin().read_line(&mut confirmation).expect("You entered incorrect response");

    if let Some('\n')= confirmation.chars().next_back() {
        confirmation.pop();
    }

    if let Some('\r')= confirmation.chars().next_back() {
        confirmation.pop();
    }

    println!("\nYou typed: {}\n", confirmation);
    confirmation
}

fn main() {
    let args = Args::parse();
    let file: String;
    let mut lines: std::str::Lines<>;
    let path = PathBuf::from(args.source_dir.clone());

    *VERBOSE.lock().unwrap() = args.verbose;

    DIR_LIST.lock().unwrap().push(path.clone());
    match args.operation.clone() {
        Operation::Encrypt => {
            if let Some(file) = pre_validate_source(&path){
                println!("\nYikes! Found an encrypted file => {:?}, and there could be several. 
Please ensure you are not providing already encrypted files. Doing double encryption won't help", file);
                process::exit(1);
            };
        },
        Operation::Decrypt => {}
    }
    

    recurse_dirs(&path);
    
    println!("\nNote: This software is issued under the MIT or Apache 2.0 License. Understand what it means before use.\n");
    println!("\n################### Execution Begin #########################\n");
    println!("\n**** Operational Info ****\n");
    println!("{} system detected", env::consts::OS);
    println!("The source directory you provided : {}", args.source_dir);
    println!("The target director you provided : {}", args.target_dir.as_ref().unwrap_or(&"Not Specified".to_string()));
    println!("Delete the source files? : {:?}", args.delete_src);
    println!("This number of directories will be created in the target directory : {}", DIR_LIST.lock().unwrap().to_vec().capacity());
    println!("This number of files will be created in the target directory : {}", FILE_LIST.lock().unwrap().to_vec().capacity());
    println!("Total threads about to be used : {}", args.threads);
    println!("The Operation and the Mode you are about to perform on the source directory : {:?}, AES-256-{:?}", args.operation, args.mode);
    println!("The encrypted files MUST be of '.enom' extension");
    println!("\n**************************\n");

    match args.mode {
        Mode::ECB => {
            if let Ok(tmp) = fs::read_to_string(args.password_file) {
                *ECB_32BYTE_KEY.lock().unwrap() = tmp.trim().to_owned();
                if ECB_32BYTE_KEY.lock().unwrap().len() != 32 {
                    panic!("The key specified in the password file is not of 32 bytes. Did you miss characters? or did you specify a 2nd line by accident?");
                }
            } else {
                println!("\nSorry, I did not find a password-file provided as a command-line options. You need to manually enter the credentials.\n");
                *ECB_32BYTE_KEY.lock().unwrap() = prompt_password("Enter the Password: ").expect("You entered a bad password").trim().to_owned();
            }
            
        },
        Mode::GCM => {
            let (password, salt) = if let Ok(tmp) = fs::read_to_string(args.password_file) {
                
                file = tmp.clone();
                lines = file.trim().lines();
                (lines.next().expect("Password is expected").to_owned(), lines.next().expect("Salt is expected in the password-file").to_owned())
            
            } else {
                
                println!("\nSorry, I did not find a password-file provided as a command-line option. Maybe you provided but forgot to pass the file with the '.omk' extension");
                println!("Searching for a password file on your machine. It ends with the extension '.omk'");
                
                if let Some(o) = find_password_file() {
                    println!("\nDo you wish to use this file?");
                    if confirmation() == "Y" {
                        if let Ok(k) = fs::read_to_string(o) {
                            
                            file = k.clone();
                            lines = file.trim().lines();
                            (lines.next().expect("Password is expected").to_owned(), lines.next().expect("Salt is expected in the password-file").to_owned()) 
                        
                        } else {

                            println!("Failed the read the password file");
                            println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
                            password_prompt()

                        }
                    } else {
                        println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
                        password_prompt()
                    }
                   
                } else {
                    println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
                    password_prompt()
                }

            };

            //let salt = SaltString::generate(&mut OsRng);
            let key = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt.as_bytes(), args.iterations);
            let key_gen = Key::<Aes256Gcm>::from_slice(&key);
            GCM_32BYTE_KEY.lock().unwrap().push(key_gen.to_owned());
            println!("\nGenerated a key based on PBKDF2 HMAC (SHA256) function ...");

        }
    };

    let target_dir = match &args.target_dir {
        Some(f) => f.as_str(),
        None => &args.source_dir.as_str()
    };

    String::from_utf8_lossy(include_bytes!("warning.txt"))
                    .chars()
                    .for_each(|x| 
                        if Cow::<str>::Owned(x.to_string()) == "\n" { 
                            println!("");
                        } else {
                            print!("{}", x);
                        }
                    );

    println!("\nDo you wish to proceed?\n");

    if confirmation() == "Y" {
        let start_time = Instant::now();
        match args.operation {
            Operation::Encrypt => {
                create_dirs(DIR_LIST.lock().unwrap().to_vec(), Operation::Encrypt, args.source_dir.as_str(), target_dir);
                encrypt_files(FILE_LIST.lock().unwrap().to_vec(), args.threads, args.source_dir.as_str(), target_dir, args.mode, args.delete_src);
            },
            Operation::Decrypt => {
                create_dirs(DIR_LIST.lock().unwrap().to_vec(), Operation::Decrypt, args.source_dir.as_str(), target_dir);
                decrypt_files(FILE_LIST.lock().unwrap().to_vec(), args.threads, args.source_dir.as_str(), target_dir, args.mode, args.delete_src);
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
