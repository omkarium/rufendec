// Copyright (c) 2023 Venkatesh Omkaram

use indicatif::ProgressBar;
use std::{
    env, fs,
    io::{stdin, stdout, Write},
    path::PathBuf,
    time::Duration,
};
use walkdir::WalkDir;

use crate::log::{log, LogLevel};

/* This function can be used for all sorts of confirmation input from the user. */
pub fn get_confirmation() -> String {
    let mut confirmation: String = String::new();

    print!("\nPlease type Y for yes, and N for no : ");

    let _ = stdout().flush();

    stdin()
        .read_line(&mut confirmation)
        .expect("You entered incorrect response");

    if let Some('\n') = confirmation.chars().next_back() {
        confirmation.pop();
    }

    if let Some('\r') = confirmation.chars().next_back() {
        confirmation.pop();
    }

    println!("\nYou typed: {}\n", confirmation);

    confirmation
}

// This will look for password file on you system
pub fn probe_password_file<F>(f: F) -> (Option<std::string::String>, Option<std::string::String>)
where
    F: Fn() -> (Option<std::string::String>, Option<std::string::String>),
{
    let file: String;
    let mut lines: std::str::Lines;

    // If the password file is not found then look for a password file

    log(LogLevel::WARN, format!("Sorry, I did not find a password-file provided as a command-line option. Maybe you provided but forgot to pass the file with the '.omk' extension").as_str());
    println!("\nSearching for a password file on your machine. It ends with the extension '.omk'");

    // find_password_file() helps to look for a password file
    if let Some(o) = find_password_file() {
        println!("\nDo you wish to use this file?");
        if get_confirmation() == "Y" {
            if let Ok(k) = fs::read_to_string(o) {
                file = k.clone();
                lines = file.trim().lines();
                (
                    Some(lines.next().expect("Password is expected").to_owned()),
                    Some(
                        lines
                            .next()
                            .expect("Salt is expected in the password-file")
                            .to_owned(),
                    ),
                )
            } else {
                // The user chosen to use the password file found by the program, but the read failed

                println!("Failed the read the password file");
                println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");

                // Prompt the user to input the password and salt manually
                //password_prompt()
                f()
            }
        } else {
            // The password file is found in the system, but the user wished to not use it

            println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");

            // Prompt the user to input the password and salt manually
            f()
        }
    } else {
        // Prompt the user to input the password and salt manually because no password file is found on the system
        println!("\nYou need to manually enter the credentials. Credentials will not be visible as you type.");
        f()
    }
}

// This function helps to find a password file with ".omk" extension on the users system
pub fn find_password_file() -> Option<PathBuf> {
    let os_type = env::consts::OS;

    // This specifies where to look for the file
    let target_dir = match os_type {
        "linux" => vec![".", "..", "../../", "/etc", "/root", "/home"],
        "windows" => vec!["C:/WINDOWS/SYSTEM32/config", "."],
        _ => vec!["."],
    };

    for i in target_dir {
        let file_list: Vec<Result<walkdir::DirEntry, walkdir::Error>> =
            WalkDir::new(i).into_iter().collect();
        log(
            LogLevel::INFO,
            format!(
                "Searching this many files : {:?}. Please be patient",
                file_list.capacity()
            )
            .as_str(),
        );

        let bar = ProgressBar::new_spinner(); // Create a Spinner

        for entry in WalkDir::new(i)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            bar.enable_steady_tick(Duration::from_millis(100)); // Steadily spin the spinner

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
