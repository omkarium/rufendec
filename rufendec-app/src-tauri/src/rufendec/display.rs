// Copyright (c) 2023 Venkatesh Omkaram

use std::{env, path::PathBuf};
use crate::rufendec::{config::Command, operations::{HashMode, DIR_LIST, FILES_SIZE_BYTES, FILE_LIST}};
use colored::Colorize;
use human_bytes::human_bytes;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt;

#[allow(dead_code)]
pub fn terminal_suppress<F>(command: &Command,f: F) 
where F: Fn() {
    match command {
        Command::File(options) => {
            if !options.suppress_terminal {
                f()
            }
        },
        _ => {
            f()
        }
    }
}

#[allow(dead_code)]
pub fn display_operational_info(command: &Command) {
    let binding: String;
    let command_deconstruct: (
        &str, 
        &String, 
        &String, 
        bool, 
        String, 
        usize, 
        &crate::rufendec::operations::Operation, 
        crate::rufendec::operations::Mode, 
        &Option<crate::rufendec::config::Shred>, 
        bool, 
        bool,
        HashMode,
        u32,
        bool
    ) = match command {
        Command::Dir(options) => (
            "directory", 
            &options.source_dir, 
            {
                binding = options.target_dir.clone().unwrap_or("Not Specified".to_string());
                &binding
            },
            options.delete_src,
            human_bytes(*FILES_SIZE_BYTES.lock().unwrap() as f64),
            options.threads,
            &options.operation,
            options.mode,
            &options.shred,
            options.anon,
            options.verbose,
            options.hash_with,
            options.iterations,
            options.dry_run,
        ),
        Command::File(options) => (
            "file", 
            &options.source_file, 
            {
                binding = options.target_dir.clone().unwrap_or("Not Specified".to_string());
                &binding
            },            
            options.delete_src,
            {
                let source_file = &PathBuf::from(&options.source_file);
                let mut file_size= String::new();
                if let Ok(total_files_size) = source_file.metadata() {


                    if cfg!(unix) {
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        {
                            file_size = human_bytes(total_files_size.size() as f64)
                        }
                    } else if cfg!(windows) {
                        #[cfg(target_os = "windows")]
                        {
                            file_size = human_bytes(total_files_size.file_size() as f64)
                        }
                    }

                    
                } else {
                    file_size = "NA".to_string()
                }

                file_size
            },
            1,
            &options.operation,
            options.mode,
            &options.shred,
            options.anon,
            options.verbose,
            options.hash_with,
            options.iterations,
            options.dry_run,
        )
    };

    let padding = 12 - command_deconstruct.0.len(); // Calculate how many spaces to add

    println!("\nNote: This software is issued under the MIT or Apache 2.0 License. Understand what it means before use.\n");
    println!("\n**** Operational Info ****\n");
    println!("Operating system                                  : {}", env::consts::OS);
    println!("The source {} you provided {:>width$}             : {}", command_deconstruct.0, " ".repeat(padding), command_deconstruct.1, width = padding);
    println!("The target directory you provided                 : {}", command_deconstruct.2);

    let file_fate = if command_deconstruct.8.is_some() {
        "Shred".to_string()
    } else if command_deconstruct.3 {
        "Delete".to_string()
    } else {
        "Neither (files won't be removed)".to_string()
    };

    println!("Dry Run enabled?                                  : {}", command_deconstruct.13.to_string().bright_white().blink());
    println!("Shred or Delete the source file(s)?               : {}", file_fate.bright_green().bold().blink());
    println!("Anonymize the source file(s)?                     : {}", command_deconstruct.9);
    println!("Verbose mode enabled?                             : {}", command_deconstruct.10.to_string().bright_white().blink());

    if let Command::Dir(_) = command {
    println!("Total target sub-directories (to be created)      : {}", DIR_LIST.lock().unwrap().to_vec().capacity());
    println!("Total target files (to be created)                : {}", FILE_LIST.lock().unwrap().to_vec().capacity());
    }

    println!("Total size of source {} {:>width$}                : {}", command_deconstruct.0, " ".repeat(padding), command_deconstruct.4, width = padding);
    println!("Total threads about to be used                    : {}", command_deconstruct.5);
    println!("Hashing function employed                         : {:?}", command_deconstruct.11);
    println!("Iterations for the hashing function               : {}", command_deconstruct.12);
    println!("Operation chosen                                  : {}", command_deconstruct.6.to_str().bright_blue().bold().blink());
    println!("Mode chosen                                       : AES-256-{:?}", command_deconstruct.7);
    println!("\nThe encrypted files MUST be of '.enom' extension");
    println!("\n**************************\n");
    
}
