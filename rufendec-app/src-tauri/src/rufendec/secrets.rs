// Copyright (c) 2023 Venkatesh Omkaram

use std::{fs, time::Duration};

use aes_gcm::{Aes256Gcm, Key};
use indicatif::{ProgressBar, ProgressStyle};
use pbkdf2::pbkdf2_hmac_array;
use rpassword::prompt_password;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::rufendec::{
    common::probe_password_file,
    config::Command,
    display::terminal_suppress,
    log::{log, LogLevel},
    operations::{HashMode, Mode, ECB_32BYTE_KEY, GCM_32BYTE_KEY},
};

#[allow(dead_code)]
pub struct Secrets {
    password_file: String,
    passwd: Option<String>,
    salt: Option<String>,
    mode: Mode,
    suppress_terminal: bool,
    skip_passwd_file_search: bool,
    iterations: u32,
    hash_with: HashMode
}

#[allow(dead_code)]
pub fn passwd_salt_tuple_from_prompt(
    secrets: &Secrets,
) -> (Option<std::string::String>, Option<std::string::String>) {
    {
        if !secrets.skip_passwd_file_search {
            probe_password_file(|| {
                (
                    Some(
                        prompt_password("\nEnter the Password: ")
                            .expect("You entered a bad password")
                            .trim()
                            .to_owned(),
                    ),
                    Some(
                        prompt_password("\nEnter the Salt: ")
                            .expect("You entered a bad salt")
                            .trim()
                            .to_owned(),
                    ),
                )
            })
        } else {
            (
                Some(
                    prompt_password("\nEnter the Password: ")
                        .expect("You entered a bad password")
                        .trim()
                        .to_owned(),
                ),
                Some(
                    prompt_password("\nEnter the Salt: ")
                        .expect("You entered a bad salt")
                        .trim()
                        .to_owned(),
                ),
            )
        }
    }
}

#[allow(dead_code)]
pub fn generate_keys(command: &Command) {
    let secrets = match command {
        Command::Dir(dir_options) => Secrets {
            password_file: dir_options
                .password_file
                .clone()
                .unwrap_or_else(|| "".to_string()),
            passwd: None,
            salt: None,
            mode: dir_options.mode,
            suppress_terminal: false,
            skip_passwd_file_search: dir_options.skip_passwd_file_search,
            iterations: dir_options.iterations,
            hash_with: dir_options.hash_with,
        },
        Command::File(file_options) => Secrets {
            password_file: file_options
                .password_file
                .clone()
                .unwrap_or_else(|| "".to_string()),
            passwd: file_options.passwd.clone(),
            salt: file_options.salt.clone(),
            mode: file_options.mode,
            suppress_terminal: file_options.suppress_terminal,
            skip_passwd_file_search: file_options.skip_passwd_file_search,
            iterations: file_options.iterations,
            hash_with: file_options.hash_with,
        },
    };
    // First look for credentials in a password file and grab the password and salt in variables as Strings
    let (password, salt) = if let Ok(tmp) = fs::read_to_string(secrets.password_file.clone()) {
        let file: String = tmp.clone();
        let mut lines: std::str::Lines = file.trim().lines();

        (
            Some(
                lines
                    .next()
                    .unwrap_or_else(|| {
                        log(LogLevel::ERROR, "Password is expected. \n");
                        std::process::exit(1)
                    })
                    .to_owned(),
            ),
            Some(
                lines
                    .next()
                    .unwrap_or_else(|| {
                        log(LogLevel::ERROR, "Salt is expected in the password-file. \n");
                        std::process::exit(1)
                    })
                    .to_owned(),
            ),
        )
    } else {
        match command {
            Command::Dir(_) => passwd_salt_tuple_from_prompt(&secrets),
            Command::File(_) => {
                if !secrets.suppress_terminal && secrets.passwd.is_none() && secrets.salt.is_none()
                {
                    passwd_salt_tuple_from_prompt(&secrets)
                } else {
                    (Some(secrets.passwd.clone().unwrap_or_else(|| {
                            log(
                                LogLevel::ERROR,
                                "Password is expected since you did not provide a password file and the terminal IO is suppressed. \n",
                            );
                            std::process::exit(1)
                        })),
                    Some(secrets.salt.clone().unwrap_or_else(|| {
                            log(
                                LogLevel::ERROR,
                                "Salt is expected since you did not provide a password file and the terminal IO is suppressed. \n",
                            );
                            std::process::exit(1)
                        }))
                    )
                }
            }
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

    let mut key = match secrets.hash_with {
        HashMode::Argon2 => {
            pb.set_message("Generating a secure key based on Argon2ID PBKDF hashing function");

            let mut argon2_param_builder = argon2::ParamsBuilder::new();
        
            let argon2_struct = match argon2_param_builder.t_cost(secrets.iterations).p_cost(4).build() {
                Ok(o) => argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, o),
                Err(_) => argon2::Argon2::default(),
            };
            let mut key = [0u8; 32];
            
            argon2_struct.hash_password_into(
                password.unwrap().as_bytes(),
                salt.unwrap().as_bytes(),
                &mut key,
            ).expect("Failed to generate a secure key with Argon2ID");

            key
        },
        HashMode::PBKDF2 => {
            pb.set_message("Generating a secure key based on PBKDF2 HMAC (SHA256) function");

            // Use let salt = SaltString::generate(&mut OsRng) to generate a truly random salt;
        
            // Using the PBKDF2 SHA256 function generate a 32 byte key array based on the password and the salt provided as bytes, and the number of iterations
            pbkdf2_hmac_array::<Sha256, 32>(
                password.unwrap().as_bytes(),
                salt.unwrap().as_bytes(),
                secrets.iterations,
            )

        },
    };

    

    

    // Generate a Key of type Generic Array which can be used by the core AES GCM module from the 32 byte key array
    let mut key_gen = Key::<Aes256Gcm>::clone_from_slice(key.as_slice());

    // Helps to get encryption credentials from the user
    match secrets.mode {
        Mode::ECB => {
            // ECB_32BYTE_KEY is a vec which holds the key_gen. This is done because &GenericArray<> cannot be easily passed into a RwLock which is needed for Multithreading
            ECB_32BYTE_KEY.write().unwrap().push(key_gen);
        }

        Mode::GCM => {
            // GCM_32BYTE_KEY is a vec which holds the key_gen. This is done because &GenericArray<> cannot be easily passed into a RwLock which is needed for Multithreading
            GCM_32BYTE_KEY.write().unwrap().push(key_gen);
        }
    };

    terminal_suppress(command, || {
        println!("\n\nKey generation complete ...\n\n");
    });

    key.zeroize();
    key_gen.zeroize();
}

pub fn clear_keys() {
    // Zeroize all keys in ECB vector and clear it
    {
        let mut ecb_keys = ECB_32BYTE_KEY.write().unwrap();
        for key in ecb_keys.iter_mut() {
            key.zeroize();
        }
        ecb_keys.clear();
    }
    
    // Zeroize all keys in GCM vector and clear it
    {
        let mut gcm_keys = GCM_32BYTE_KEY.write().unwrap();
        for key in gcm_keys.iter_mut() {
            key.zeroize();
        }
        gcm_keys.clear();
    }
}

pub fn verify_keys_cleared(mode: Mode) {
    match mode {
        Mode::ECB => {
            let ecb_keys = ECB_32BYTE_KEY.read().unwrap();
            assert!(ecb_keys.is_empty(), "ECB keys vector should be empty after clearing");
        },
        Mode::GCM => {
            let gcm_keys = GCM_32BYTE_KEY.read().unwrap();
            assert!(gcm_keys.is_empty(), "GCM keys vector should be empty after clearing");
        },
    }
}
