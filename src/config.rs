    // Copyright (c) 2023 Venkatesh Omkaram

    use clap::Parser;
    use crate::operations::{Operation, Mode};

    // Using Clap library to provide the user with CLI argument parser and help section.
    #[derive(Parser)]
    #[command(author="@github.com/omkarium", version, about, long_about = None)]
    pub struct Args {
        /// Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
        pub source_dir: String,
        /// Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go).
        /// But if you do not provide this, the target files will be placed in the Source Dir. 
        /// To delete the source files make sure you pass option -d
        pub target_dir: Option<String>,
        /// Enter the password file with an extension ".omk". The first line in the file must have the password, and If you choose mode=gcm then ensure to pass the "Salt" in the 2nd line
        #[arg(short, long, default_value_t = String::new())]
        pub password_file: String,
        /// Skip the password_file search on the machine if in case you decide to not provide the password_file in the CLI options
        #[clap(short, long, default_value_t = false)]
        pub skip_passwd_file_search: bool, 
        /// Enter the Operation you want to perform on the Source Dir
        #[clap(short, long, value_enum)]    
        pub operation: Operation,
        /// Provide the mode of Encryption here
        #[clap(short, long, value_enum, default_value_t = Mode::GCM)]    
        pub mode: Mode,
        /// Pass this option to delete the source files in the Source Dir
        #[clap(short, long, default_value_t = false)]
        pub delete_src: bool,
        /// Threads to speed up the execution
        #[clap(short, long, default_value_t = 8)]
        pub threads: usize,
        /// Iterations for PBKDF2
        #[clap(short, long, default_value_t = 60_000)]
        pub iterations: u32,
        /// Print verbose output
        #[clap(short, long, default_value_t = false)]
        pub verbose: bool    

    }