// Copyright (c) 2023 Venkatesh Omkaram

use chrono::{DateTime, Local};
use colored::Colorize;

pub enum LogLevel {
    INFO,
    ERROR,
    WARN
}

pub fn log(level: LogLevel, message: &str) {
    let timestamp_fmt: &str = "[%Y-%m-%d %H:%M:%S.%3f]";
    let now = Local::now();
    let timestamp: DateTime<Local> =
        DateTime::from_naive_utc_and_offset(now.naive_utc(), *now.offset());
    let colored_level = match level {
        LogLevel::INFO => "INFO".bright_yellow(),
        LogLevel::ERROR => "ERROR".bright_red(),
        LogLevel::WARN => "WARN".bright_cyan(),
    };
    let print = format!(
        "\n{} {}: {}",
        timestamp.format(timestamp_fmt),
        colored_level,
        message
    );

    match level {
        LogLevel::INFO => println!("{}", print),
        LogLevel::ERROR => eprintln!("{}", print),
        LogLevel::WARN => eprintln!("{}", print),
    }
}