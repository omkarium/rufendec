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

// Copyright (c) 2023 Venkatesh Omkaram

mod common;
mod config;
mod display;
mod log;
mod operations;
mod secrets;

use crate::common::get_confirmation;
use crate::config::{Args, Command};
use crate::log::{log, LogLevel};
use crate::operations::{
    create_dirs, decrypt_files, encrypt_files, pre_validate_source, recurse_dirs, DIR_LIST,
    FAILED_COUNT, FILES_SIZE_BYTES, FILE_LIST, SUCCESS_COUNT, VERBOSE,
};
use crate::operations::{Mode, Operation};
use clap::Parser;
use colored::Colorize;
use display::{display_operational_info, terminal_supress};
use human_bytes::human_bytes;
use secrets::{clear_keys, generate_keys, verify_keys_cleared};
use std::{borrow::Cow, path::PathBuf, time::Instant};

// Program execution begins here
fn main() {
    // Get the input arguments and options from the CLI passed by the user
    let command = Args::parse().command;

    terminal_supress(&command, || {
        println!(
            "\n@@@@@@@@@@@@@@@@@@@ Rufendec ({}) @@@@@@@@@@@@@@@@@@@\n",
            "by Omkarium".green().bold()
        );
        println!("\n{}\n", 
            "[Please read the documentation at https://github.com/omkarium/rufendec before you use this program]".bright_magenta());
    });

    match &command {
        Command::Dir(options) => {
            let path = PathBuf::from(&options.source_dir);

            *VERBOSE.write().unwrap() = options.verbose;

            /* DIR_LIST is the directory list. It is used to gather the list of sub directories the source directory has
            later will be used to create the same directory structure in the target
            The Source directory path first needs to be pushed to DIR_LIST. That way when the
            create_dirs() function is called, the source directory base path will be replace by the target path specified.
            */
            DIR_LIST.lock().unwrap().push(path.clone());

            // Validates whether any Illegal source dir path is provided
            // Validates whether any encrypted files are present in the source directory while the operation the user choose is to Encrypt
            pre_validate_source(&path, &options.operation);

            // Recursively walk through the source directory and list all the sub-directory names and push it to a collection
            recurse_dirs(&path);

            display_operational_info(&command);

            let total_files_size = FILES_SIZE_BYTES.lock().unwrap();

            generate_keys(&command);

            // Capture the target dir path by using the target_dir arg the user passed, if not then use the source directory to place the target files
            let target_dir = match &options.target_dir {
                Some(f) => f.as_str(),
                None => &options.source_dir.as_str(),
            };

            // Read the notice from the notice.txt file which resides in the binary file as bytes.
            // Print the notice text exactly the same way it is represented in the notice.txt file
            String::from_utf8_lossy(include_bytes!("notice.txt"))
                .chars()
                .for_each(|x| {
                    if Cow::<str>::Owned(x.to_string()) == "\n" {
                        println!("");
                    } else {
                        print!(
                            "{}",
                            x.to_string()
                                .bright_white()
                                .bold()
                                .on_custom_color((54, 69, 79))
                        );
                    }
                });

            // Ask if the user wish to proceed for further. If No, quit the program
            println!("\n\nDo you wish to proceed further?\n");

            if get_confirmation() == "Y" {
                // Capture the start time of the execution
                let start_time = Instant::now();
                match options.operation {
                    Operation::Encrypt => {
                        // Create the target directory and sub-directories first. Encrypt the files and place them in the target
                        create_dirs(
                            DIR_LIST.lock().unwrap().to_vec(),
                            options.source_dir.as_str(),
                            target_dir,
                        );
                        encrypt_files(
                            FILE_LIST.lock().unwrap().to_vec(),
                            options.threads,
                            options.source_dir.as_str(),
                            target_dir,
                            options.mode,
                            options.delete_src,
                        );
                    }
                    Operation::Decrypt => {
                        // Create the target directory and sub-directories first. Decrypt the files and place them in the target
                        create_dirs(
                            DIR_LIST.lock().unwrap().to_vec(),
                            options.source_dir.as_str(),
                            target_dir,
                        );
                        decrypt_files(
                            FILE_LIST.lock().unwrap().to_vec(),
                            options.threads,
                            options.source_dir.as_str(),
                            target_dir,
                            options.mode,
                            options.delete_src,
                        );
                    }
                }

                clear_keys();
                verify_keys_cleared(options.mode);

                // Capture the elapsed time of the execution
                let elapsed = Some(start_time.elapsed());

                println!(
                    "\n============== {} ===============\n",
                    "Result".bright_blue()
                );
                println!(
                    "Finished {:?}ion in {:?}, at a rate of {}/sec",
                    options.operation,
                    elapsed.unwrap(),
                    human_bytes(*total_files_size as f64 / elapsed.unwrap().as_secs_f64())
                );
                println!("\nSuccessfully cleared the credentials from the memory");

                // Success and failed count of files which are either encrypted or decrypted is currently only possible mode GCM
                if options.mode.to_string() == "GCM" {
                    println!(
                        "\nTotal Success count: {}",
                        SUCCESS_COUNT
                            .lock()
                            .unwrap()
                            .to_string()
                            .bright_purple()
                            .bold()
                            .blink()
                    );
                    println!(
                        "Total failure count: {}",
                        FAILED_COUNT
                            .lock()
                            .unwrap()
                            .to_string()
                            .bright_purple()
                            .bold()
                            .blink()
                    );
                }

                // Print if the failed file count is greater than 0
                if *FAILED_COUNT.lock().unwrap() > 0 {
                    println!("\nLooks like we got some failures 😰");
                    println!("\nPlease check whether you provided the correct password (and the salt in case you are using GCM mode)");
                    println!("\nFailures can also occur when you have the target files already present in the target directory");
                } else {
                    match options.mode {
                            Mode::GCM => {},
                            Mode::ECB => println!("\nThe result cannot be determined for ECB mode. Manually check if the target file is created."),
                        }
                    println!("\nWe are done. Enjoy hacker!!! 😎");
                }

                println!("\n=================================\n");
            } else {
                println!(
                    "\nPhew... You QUIT! Guess you really know what you are doing. Good choice.\n"
                );
            }
        }
        Command::File(options) => {
            let source_file = &PathBuf::from(&options.source_file);
            let mut source_file_path_vec: Vec<PathBuf> = Vec::new();
            source_file_path_vec.push(source_file.to_path_buf());

            *VERBOSE.write().unwrap() = options.verbose;

            if let Ok(_) = source_file.metadata() {
                terminal_supress(&command, || display_operational_info(&command));

                generate_keys(&command);

                if let Some(source_dir) = source_file.parent() {
                    if let Some(source_dir) = source_dir.to_str() {
                        // Capture the target dir path by using the target_dir arg the user passed, if not then use the source directory to place the target files
                        let target_dir = match &options.target_dir {
                            Some(f) => f.as_str(),
                            None => &source_dir,
                        };

                        match options.operation {
                            Operation::Encrypt => {
                                encrypt_files(
                                    source_file_path_vec,
                                    1,
                                    source_dir,
                                    target_dir,
                                    options.mode,
                                    options.delete_src,
                                );
                            }
                            Operation::Decrypt => {
                                decrypt_files(
                                    source_file_path_vec,
                                    1,
                                    source_dir,
                                    target_dir,
                                    options.mode,
                                    options.delete_src,
                                );
                            }
                        }
                    }
                }

                clear_keys();
                verify_keys_cleared(options.mode);

                terminal_supress(&command, || {
                    println!("Successfully cleared the credentials from the memory");

                    println!(
                        "\nAES-256 {} {:?}ion is {}",
                        &options.mode,
                        &options.operation,
                        "completed".to_string().bright_green().bold().blink()
                    );

                    // Print if the failed file count is greater than 0
                    if *FAILED_COUNT.lock().unwrap() > 0 {
                        println!("\nLooks like we had a failure 😰");
                        println!("\nPlease check whether you provided the correct password (and the salt in case you are using GCM mode)");
                    } else {
                        match options.mode {
                                Mode::GCM => println!("\nNo errors occurred 😎"),
                                Mode::ECB => println!("\nThe result cannot be determined for ECB mode. Manually check if the target file is created."),
                            }
                    }
                });
            } else {
                log(
                    LogLevel::ERROR,
                    "The source_file specified cannot be found. \n",
                );
            }
        }
    };
}
