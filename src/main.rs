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

// The lines above are used to generate Rust documentation. Program code starts from the below.

mod operations;

use clap::Parser;
use std::{borrow::Cow, fs, io::{stdin,stdout,Write}, path::PathBuf, time::Instant};
use crate::operations::{
    create_dirs, decrypt_files, encrypt_files, find_password_file, pre_validate_source, recurse_dirs, 
    DIR_LIST, ECB_32BYTE_KEY, FAILED_COUNT, FILE_LIST, GCM_32BYTE_KEY, SUCCESS_COUNT, VERBOSE, FILES_SIZE_BYTES
};
use crate::operations::{Operation, Mode};
use rpassword::prompt_password;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key};
use std::env;
use human_bytes::human_bytes;

// Using Clap library to provide the user with CLI argument parser and help section.
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

/* This function prompts the user to input a pass and salt when the user does not specify a password file using -p option. 
   This is only used for GCM Mode
*/
fn password_prompt() -> (String, String) {
    (prompt_password("Enter the Password: ").expect("You entered a bad password").trim().to_owned(),
    prompt_password("\nEnter the Salt: ").expect("You entered a bad salt").trim().to_owned())
}

/* This function can be used for all sorts of confirmation input from the user. */
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

// Program execution begins here
fn main() {

    // Get the input arguments and options from the CLI passed by the user
    let args = &Args::parse();

    let file: String;
    let mut lines: std::str::Lines<>;
    let path = PathBuf::from(&args.source_dir);

    *VERBOSE.lock().unwrap() = args.verbose;

    /* DIR_LIST is the directory list. It is used to gather the list of sub directories the source directory has
       later will be used to create the same directory structure in the target 
       The Source directory path first needs to be pushed to DIR_LIST. That way when the
       create_dirs() function is called, the source directory base path will be replace by the target path specified.
     */ 
    DIR_LIST.lock().unwrap().push(path.clone());


    // Validates whether any Illegal source dir path is provided
    // Validates whether any encrypted files are present in the source directory while the operation the user choose is to Encrypt
    pre_validate_source(&path, &args.operation);
    
    // Recursively walk through the source directory and list all the sub-directory names and push it to a collection
    recurse_dirs(&path);
    
    let total_files_size = FILES_SIZE_BYTES.lock().unwrap();

    println!("\nNote: This software is issued under the MIT or Apache 2.0 License. Understand what it means before use.\n");
    println!("\n################### Execution Begin #########################\n");
    println!("\n**** Operational Info ****\n");
    println!("Operating system                              : {}", env::consts::OS);
    println!("The source directory you provided             : {}", args.source_dir);
    println!("The target directory you provided             : {}", args.target_dir.as_ref().unwrap_or(&"Not Specified".to_string()));
    println!("Delete the source files?                      : {}", args.delete_src);
    println!("Total target sub-directories (to be created)  : {}", DIR_LIST.lock().unwrap().to_vec().capacity());
    println!("Total target files (to be created)            : {}", FILE_LIST.lock().unwrap().to_vec().capacity());
    println!("Total size of source directory                : {}", human_bytes(*total_files_size as f64));
    println!("Total threads about to be used                : {}", args.threads);
    println!("Operation chosen                              : {:?}", args.operation);
    println!("Mode chosen                                   : AES-256-{:?}", args.mode);
    println!("\nThe encrypted files MUST be of '.enom' extension");
    println!("\n**************************\n");

    // Helps to get encryption credentials from the user
    match args.mode {

        // If ECB mode is chosen, then ask the user only for a Password and store it in ECB_32BYTE_KEY
        Mode::ECB => {
            if let Ok(tmp) = fs::read_to_string(&args.password_file) {
                *ECB_32BYTE_KEY.lock().unwrap() = tmp.trim().to_owned();
                if ECB_32BYTE_KEY.lock().unwrap().len() != 32 {
                    panic!("The key specified in the password file is not of 32 bytes. Did you miss characters? or did you specify a 2nd line by accident?");
                }
            } else {
                println!("\nSorry, I did not find a password-file provided as a command-line options. You need to manually enter the credentials.\n");
                *ECB_32BYTE_KEY.lock().unwrap() = prompt_password("Enter the Password: ").expect("You entered a bad password").trim().to_owned();
            }
            
        },

        // If GCM mode is chosen, then ask the user for Password and Salt, and store the final key in GCM_32BYTE_KEY
        Mode::GCM => {

            // First look for credentials in a password file and grab the password and salt in variables as Strings
            let (password, salt) = if let Ok(tmp) = fs::read_to_string(&args.password_file) {
                
                file = tmp.clone();
                lines = file.trim().lines();
                (lines.next().expect("Password is expected").to_owned(), lines.next().expect("Salt is expected in the password-file").to_owned())
            
            } else {
                // If the password file is not found then look for a password file
                
                println!("\nSorry, I did not find a password-file provided as a command-line option. Maybe you provided but forgot to pass the file with the '.omk' extension");
                println!("Searching for a password file on your machine. It ends with the extension '.omk'");
                
                // find_password_file() helps to look for a password file
                if let Some(o) = find_password_file() {
                    println!("\nDo you wish to use this file?");
                    if confirmation() == "Y" {
                        if let Ok(k) = fs::read_to_string(o) {
                            
                            file = k.clone();
                            lines = file.trim().lines();
                            (lines.next().expect("Password is expected").to_owned(), lines.next().expect("Salt is expected in the password-file").to_owned()) 
                        
                        } else {
                            // The user chosen to use the password file found by the program, but the read failed

                            println!("Failed the read the password file");
                            println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
                            
                            // Prompt the user to input the password and salt manually
                            password_prompt()

                        }
                    } else {
                        // The password file is found in the system, but the user wished to not use it
                        
                        println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
                        
                        // Prompt the user to input the password and salt manually
                        password_prompt()
                    }
                   
                } else {
                    // Prompt the user to input the password and salt manually because no password file is found on the system
                    println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
                    password_prompt()
                }

            };

            // Use let salt = SaltString::generate(&mut OsRng) to generate a truly random salt;

            // Using the PBKDF2 SHA256 function generate a 32 byte key array based on the password and the salt provided as bytes, and the number of iterations
            let key = pbkdf2_hmac_array::<Sha256, 32>(password.as_bytes(), salt.as_bytes(), args.iterations);
            
            // Generate a Key of type Generic Array which can be used by the core AES GCM module from the 32 byte key array
            let key_gen = Key::<Aes256Gcm>::from_slice(&key);

            // GCM_32BYTE_KEY is a vec which holds the key_gen. This is done because &GenericArray<> cannot be easily passed into a Mutex which is needed for Multithreading
            GCM_32BYTE_KEY.lock().unwrap().push(key_gen.to_owned());
            println!("\nGenerated a key based on PBKDF2 HMAC (SHA256) function ...");

        }
    };

    // Capture the target dir path by using the target_dir arg the user passed, if not then use the source directory to place the target files
    let target_dir = match &args.target_dir {
        Some(f) => f.as_str(),
        None => &args.source_dir.as_str()
    };

    // Read the Extreme Warning message from the warning.txt file which resides in the binary file as bytes.
    // Print the warning text exactly the same way it is represented in the warning.txt file
    String::from_utf8_lossy(include_bytes!("warning.txt"))
                    .chars()
                    .for_each(|x| 
                        if Cow::<str>::Owned(x.to_string()) == "\n" { 
                            println!("");
                        } else {
                            print!("{}", x);
                        }
                    );
    // Ask if the user wish to proceed for further. If No, quit the program
    println!("\nDo you wish to proceed further?\n");

    if confirmation() == "Y" {

        // Capture the start time of the execution
        let start_time = Instant::now();
        match args.operation {
            Operation::Encrypt => {
                // Create the target directory and sub-directories first. Encrypt the files and place them in the target
                create_dirs(DIR_LIST.lock().unwrap().to_vec(), args.source_dir.as_str(), target_dir);
                encrypt_files(FILE_LIST.lock().unwrap().to_vec(), args.threads, args.source_dir.as_str(), target_dir, args.mode, args.delete_src);
            },
            Operation::Decrypt => {
                // Create the target directory and sub-directories first. Decrypt the files and place them in the target
                create_dirs(DIR_LIST.lock().unwrap().to_vec(), args.source_dir.as_str(), target_dir);
                decrypt_files(FILE_LIST.lock().unwrap().to_vec(), args.threads, args.source_dir.as_str(), target_dir, args.mode, args.delete_src);
            }
        }

        // Capture the elapsed time of the execution
        let elapsed = Some(start_time.elapsed());
        println!("\n============Results==============\n");
        println!("Finished {:?}ion in {:?}, at a rate of {}/sec", args.operation, elapsed.unwrap(), human_bytes(*total_files_size as f64/elapsed.unwrap().as_secs_f64()));

        // Success and failed count of files which are either encrypted or decrypted is currently only possible mode GCM
        if args.mode.to_string() == "GCM" {
            println!("\nTotal Success count: {}", SUCCESS_COUNT.lock().unwrap());
            println!("Total failure count: {}", FAILED_COUNT.lock().unwrap());
        }

        // Print if the failed file count is greater than 0
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
