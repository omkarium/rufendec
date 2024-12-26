// Copyright (c) 2023 Venkatesh Omkaram

use crate::operations::{Mode, Operation};
use clap::Parser;

// Using Clap library to provide the user with CLI argument parser and help section.
#[derive(clap::Args, Debug, Clone)]
#[command(disable_version_flag = true)]
pub struct DirOptions {
    /// Specify the Source Directory here
    pub source_dir: String,
    /// Specify the Target Directory here.
    /// But if you do not provide this, the target files will be placed in the Source Directory.
    pub target_dir: Option<String>,
    /// Specify the password file with an extension ".omk". The first line in the file must have the password, and the second line must have the salt
    #[arg(short = 'f', long)]
    pub password_file: Option<String>,
    /// Skip the password_file search on the machine if in case you decide to not provide the password_file in the CLI options
    #[clap(short = 'k', long, default_value_t = false)]
    pub skip_passwd_file_search: bool,
    /// Specify the Operation you want to perform on the Source Directory
    #[clap(short, long, value_enum)]
    pub operation: Operation,
    /// Provide the mode of Encryption here
    #[clap(short, long, value_enum, default_value_t = Mode::GCM)]
    pub mode: Mode,
    /// Pass this option to delete the source files in the Source Directory
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
    pub verbose: bool,
}

// Using Clap library to provide the user with CLI argument parser and help section.
#[derive(clap::Args, Debug, Clone)]
#[command(disable_version_flag = true)]
pub struct FileOptions {
    /// Specify the Source file here (This is the file you want to either Encrypt or Decrypt)
    pub source_file: String,
    /// Specify the Target directory here.
    /// But if you do not provide this, the target file will be placed in the source file's Directory.
    pub target_dir: Option<String>,
    /// Specify the password file with an extension ".omk". The first line in the file must have the password, and the second line must have the salt
    #[arg(short = 'f', long)]
    pub password_file: Option<String>,
    /// Skip the password_file search on the machine in case you decide to not provide the `password_file` in the CLI options
    #[clap(short = 'k', long, default_value_t = false)]
    pub skip_passwd_file_search: bool,
    /// Specify the password (in case `password_file` is not provided and `supress_terminal`` is set to true)
    #[arg(short, long)]
    pub passwd: Option<String>,
    /// Specify the salt (in case `password_file` is not provided and `supress_terminal` is set to true)
    #[arg(short, long)]
    pub salt: Option<String>,
    /// Specify the Operation you want to perform on the Source file
    #[clap(short, long, value_enum)]
    pub operation: Operation,
    /// Provide the mode of Encryption here
    #[clap(short, long, value_enum, default_value_t = Mode::GCM)]
    pub mode: Mode,
    /// Pass this option to delete the source file
    #[clap(short, long, default_value_t = false)]
    pub delete_src: bool,
    /// Iterations for PBKDF2
    #[clap(short, long, default_value_t = 60_000)]
    pub iterations: u32,
    /// Supress all CLI output
    #[clap(short = 'z', long, default_value_t = false)]
    pub supress_terminal: bool,
    /// Print verbose output
    #[clap(short, long, default_value_t = false)]
    pub verbose: bool,
}

#[derive(clap::Subcommand, Debug, Clone)]
//#[command(disable_version_flag = true)]
pub enum Command {
    /// Targets on the directory/folder level
    Dir(DirOptions),
    /// Targets on the file level
    File(FileOptions),
}

#[derive(Parser, Clone)]
#[command(author="@github.com/omkarium", version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}