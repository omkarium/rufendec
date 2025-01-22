// Copyright (c) 2023 Venkatesh Omkaram

use std::{fs, time::Duration};

use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use aes_gcm::{Aes256Gcm, Key};
use zeroize::Zeroize;

use crate::{common::probe_password_file, config::Command, display::terminal_supress, log::{log, LogLevel}, operations::{Mode, ECB_32BYTE_KEY, GCM_32BYTE_KEY}};

pub struct Secrets {
    password_file: String,
    passwd: Option<String>,
    salt: Option<String>,
    mode: Mode,
    supress_terminal: bool,
    skip_passwd_file_search: bool,
    iterations: u32
}

pub fn passwd_salt_tuple_from_prompt(secrets : &Secrets) -> (Option<std::string::String>, Option<std::string::String>) {
    {if !secrets.skip_passwd_file_search {
        probe_password_file(|| { 
            (Some(prompt_password("\nEnter the Password: ").expect("You entered a bad password").trim().to_owned()),
            Some(prompt_password("\nEnter the Salt: ").expect("You entered a bad salt").trim().to_owned()))
        })
    } else {
        (Some(prompt_password("\nEnter the Password: ").expect("You entered a bad password").trim().to_owned()),
        Some(prompt_password("\nEnter the Salt: ").expect("You entered a bad salt").trim().to_owned()))
    }}
}

pub fn generate_keys(command: &Command) {

    let secrets = match command {
        Command::Dir(dir_options) => Secrets {
            password_file: dir_options.password_file.clone().unwrap_or_else(|| "".to_string()),
            passwd: None,
            salt: None,
            mode: dir_options.mode,
            supress_terminal: false,
            skip_passwd_file_search: dir_options.skip_passwd_file_search,
            iterations: dir_options.iterations
        },
        Command::File(file_options) => Secrets {
            password_file: file_options.password_file.clone().unwrap_or_else(|| "".to_string()),
            passwd: file_options.passwd.clone(),
            salt: file_options.salt.clone(),
            mode: file_options.mode,
            supress_terminal: file_options.supress_terminal,
            skip_passwd_file_search: file_options.skip_passwd_file_search,
            iterations: file_options.iterations

        },
    };
     // First look for credentials in a password file and grab the password and salt in variables as Strings
     let (password, salt) = if let Ok(tmp) = fs::read_to_string(secrets.password_file.clone()) {
        let file: String = tmp.clone();
        let mut lines: std::str::Lines<> = file.trim().lines();

        (
            Some(lines.next().unwrap_or_else(|| {
                log(
                    LogLevel::ERROR,
                    "Password is expected. \n",
                );
                std::process::exit(1)
            }).to_owned()), 
            Some(
                lines.next().unwrap_or_else(|| {
                    log(
                        LogLevel::ERROR,
                        "Salt is expected in the password-file. \n",
                    );
                    std::process::exit(1)
                }).to_owned())
        )
    
    } else {
        match command {
            Command::Dir(_) => passwd_salt_tuple_from_prompt(&secrets),
            Command::File(_) => {
                if !secrets.supress_terminal && secrets.passwd.is_none() && secrets.salt.is_none() {
                    passwd_salt_tuple_from_prompt(&secrets)
                } else {
                    (Some(secrets.passwd.clone().unwrap_or_else(|| {
                            log(
                                LogLevel::ERROR,
                                "Password is expected since you did not provide a password file and the terminal IO is supressed. \n",
                            );
                            std::process::exit(1)
                        })),
                    Some(secrets.salt.clone().unwrap_or_else(|| {
                            log(
                                LogLevel::ERROR,
                                "Salt is expected since you did not provide a password file and the terminal IO is supressed. \n",
                            );
                            std::process::exit(1)
                        }))
                    )
                }
            },
        }
        
    };

    let pb = ProgressBar::new_spinner();

            pb.enable_steady_tick(Duration::from_millis(120));
            pb.set_style(
                ProgressStyle::with_template("\n{spinner:.blue} {msg} {spinner:.blue}")
                    .unwrap()
                    // For more spinners check out the cli-spinners project:
                    // https://github.com/sindresorhus/cli-spinners/blob/master/spinners.json
                    .tick_strings(&[
                        "▹▹▹▹▹",
                        "▸▹▹▹▹",
                        "▹▸▹▹▹",
                        "▹▹▸▹▹",
                        "▹▹▹▸▹",
                        "▹▹▹▹▸",
                        "▪▪▪▪▪",
                    ]),
            );

    pb.set_message("Generating a secure key based on PBKDF2 HMAC (SHA256) function");

    // Use let salt = SaltString::generate(&mut OsRng) to generate a truly random salt;

    // Using the PBKDF2 SHA256 function generate a 32 byte key array based on the password and the salt provided as bytes, and the number of iterations
    let mut key = pbkdf2_hmac_array::<Sha256, 32>(password.unwrap().as_bytes(), salt.unwrap().as_bytes(), secrets.iterations);
    
    // Generate a Key of type Generic Array which can be used by the core AES GCM module from the 32 byte key array
    let mut key_gen = Key::<Aes256Gcm>::clone_from_slice(key.as_slice());

    // Helps to get encryption credentials from the user
    match secrets.mode {
                        
        Mode::ECB => {
            // ECB_32BYTE_KEY is a vec which holds the key_gen. This is done because &GenericArray<> cannot be easily passed into a RwLock which is needed for Multithreading
            ECB_32BYTE_KEY.write().unwrap().push(key_gen);
        },

        Mode::GCM => {
            // GCM_32BYTE_KEY is a vec which holds the key_gen. This is done because &GenericArray<> cannot be easily passed into a RwLock which is needed for Multithreading
            GCM_32BYTE_KEY.write().unwrap().push(key_gen);            
        }
    };

    terminal_supress(command, || {
        println!("\n\nKey generation complete ...\n\n");
    });

    key.zeroize();
    key_gen.zeroize();

    
}

pub fn clear_keys() {
    if let Some(key_gen) = ECB_32BYTE_KEY.write().unwrap().get_mut(0) {
        key_gen.zeroize();
    }

    if let Some(key_gen) = GCM_32BYTE_KEY.write().unwrap().get_mut(0) {
        key_gen.zeroize();
    }
}

pub fn verify_keys_cleared(mode: Mode){
    match mode {
        Mode::ECB =>  assert_eq!(ECB_32BYTE_KEY.read().unwrap().get(0).unwrap().as_slice(), &[0;32]),
        Mode::GCM => assert_eq!(GCM_32BYTE_KEY.read().unwrap().get(0).unwrap().as_slice(), &[0;32])
    }
}