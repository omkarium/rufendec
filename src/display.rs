// Copyright (c) 2023 Venkatesh Omkaram

use std::{env, path::PathBuf};
use crate::{config::Command, operations::{DIR_LIST, FILES_SIZE_BYTES, FILE_LIST}};
use human_bytes::human_bytes;

pub fn terminal_supress<F>(command: &Command,f: F) 
where F: Fn() {
    match command {
        Command::File(options) => {
            if !options.supress_terminal {
                f()
            }
        },
        _ => {
            f()
        }
    }
}

pub fn display_operational_info(command: &Command) {

    let command_deconstruct = match command {
        Command::Dir(options) => (
            "directory", 
            &options.source_dir, 
            &options.target_dir.clone().unwrap_or("Not Specified".to_string()),
            options.delete_src,
            human_bytes(*FILES_SIZE_BYTES.lock().unwrap() as f64),
            options.threads,
            &options.operation,
            options.mode
        ),
        Command::File(options) => (
            "file", 
            &options.source_file, 
            &options.target_dir.clone().unwrap_or("Not Specified".to_string()),
            options.delete_src,
            {
                let source_file = &PathBuf::from(&options.source_file);
                if let Ok(total_files_size) = source_file.metadata() {
                    #[cfg(target_os = "linux")]
                    use std::os::unix::fs::MetadataExt;
    
                    #[cfg(target_os = "windows")]
                    use std::os::windows::fs::MetadataExt;

                    human_bytes(total_files_size.size() as f64)
                } else {
                    "NA".to_string()
                }
            },
            1,
            &options.operation,
            options.mode
        )
    };

    let padding = 12 - command_deconstruct.0.len(); // Calculate how many spaces to add

    println!("\nNote: This software is issued under the MIT or Apache 2.0 License. Understand what it means before use.\n");
    println!("\n**** Operational Info ****\n");
    println!("Operating system                                  : {}", env::consts::OS);
    println!("The source {} you provided {:>width$}             : {}", command_deconstruct.0, " ".repeat(padding), command_deconstruct.1, width = padding);
    println!("The target directory you provided                 : {}", command_deconstruct.2);
    println!("Delete the source file(s)?                        : {}", command_deconstruct.3);

    if let Command::Dir(_) = command {
    println!("Total target sub-directories (to be created)      : {}", DIR_LIST.lock().unwrap().to_vec().capacity());
    println!("Total target files (to be created)                : {}", FILE_LIST.lock().unwrap().to_vec().capacity());
    }

    println!("Total size of source {} {:>width$}                : {}", command_deconstruct.0, " ".repeat(padding), command_deconstruct.4, width = padding);
    println!("Total threads about to be used                    : {}", command_deconstruct.5);
    println!("Operation chosen                                  : {:?}", command_deconstruct.6);
    println!("Mode chosen                                       : AES-256-{:?}", command_deconstruct.7);
    println!("\nThe encrypted files MUST be of '.enom' extension");
    println!("\n**************************\n");
    
}