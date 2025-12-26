use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt;

use crate::rufendec::{
    operations::{encrypt_files, decrypt_files, pre_validate_source, recurse_dirs, create_dirs, DIR_LIST, FILE_LIST, FILES_SIZE_BYTES, SUCCESS_COUNT, FAILED_COUNT, VERBOSE, APP_HANDLE, Mode, Operation, HashMode, ECB_32BYTE_KEY, GCM_32BYTE_KEY},
    secrets::{clear_keys, verify_keys_cleared},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionOptions {
    pub source_path: String,
    pub target_path: Option<String>,
    pub password: String,
    pub salt: String,
    pub operation: String, // "encrypt" or "decrypt"
    pub mode: String, // "ecb" or "gcm"
    pub hash_with: String, // "argon2" or "pbkdf2"
    pub iterations: u32,
    pub threads: usize,
    pub delete_src: bool,
    pub anon: bool,
    pub dry_run: bool,
    pub verbose: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionResult {
    pub success: bool,
    pub message: String,
    pub success_count: u16,
    pub failed_count: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProgressUpdate {
    pub current: u64,
    pub total: u64,
    pub percentage: f64,
    pub message: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerboseMessage {
    pub message: String,
    pub level: String, // "info", "warn", "error"
}

#[derive(Debug, Serialize, Deserialize)]
struct OperationalInfo {
    file_count: usize,
    folder_count: usize,
    total_size_bytes: u64,
    total_size_human: String,
    operating_system: String,
}

// Progress tracking function that runs in a separate thread
fn track_progress(app_handle: AppHandle, total_files: usize, stop_flag: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            let current = *SUCCESS_COUNT.lock().unwrap() as u64 + *FAILED_COUNT.lock().unwrap() as u64;
            let total = total_files as u64;
            let percentage = if total > 0 {
                (current as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            let progress = ProgressUpdate {
                current,
                total,
                percentage,
                message: format!("Processing file {} of {}", current, total),
            };

            let _ = app_handle.emit("progress-update", &progress);

            std::thread::sleep(Duration::from_millis(100)); // Update every 100ms
        }
    });
}

#[tauri::command]
pub async fn encrypt_directory(app_handle: AppHandle, options: EncryptionOptions) -> Result<EncryptionResult, String> {
    let source_path = PathBuf::from(&options.source_path);
    
    // Validate source
    let operation = match options.operation.as_str() {
        "encrypt" => Operation::Encrypt,
        "decrypt" => Operation::Decrypt,
        _ => return Err("Invalid operation".to_string()),
    };
    
    // Set AppHandle for logger macro to emit events BEFORE validation
    // This ensures validation errors appear in the UI
    *APP_HANDLE.lock().unwrap() = Some(app_handle.clone());
    
    // Set verbose mode based on user preference (don't force it for validation)
    *VERBOSE.write().unwrap() = options.verbose;
    
    // Validate source and handle errors
    match pre_validate_source(&source_path, &operation) {
        Ok(_) => {},
        Err(e) => {
            // Emit error to verbose log - always show errors even if verbose is disabled
            use serde::{Serialize, Deserialize};
            #[derive(Serialize, Deserialize)]
            struct VerboseMsg {
                message: String,
                level: String,
            }
            let error_msg = VerboseMsg {
                message: e.clone(),
                level: "error".to_string(),
            };
            let _ = app_handle.emit("verbose-message", &error_msg);
            let _ = app_handle.emit("show-verbose-container", &());
            // Clear AppHandle
            *APP_HANDLE.lock().unwrap() = None;
            return Err(e);
        }
    }
    
    // Clear previous state
    DIR_LIST.lock().unwrap().clear();
    FILE_LIST.lock().unwrap().clear();
    *FILES_SIZE_BYTES.lock().unwrap() = 0;
    *SUCCESS_COUNT.lock().unwrap() = 0;
    *FAILED_COUNT.lock().unwrap() = 0;
    
    // Clear any existing keys from previous operations
    clear_keys();
    
    // Add source directory to DIR_LIST
    DIR_LIST.lock().unwrap().push(source_path.clone());
    
    // Recurse directories and collect files
    recurse_dirs(&source_path);
    
    let total_files = FILE_LIST.lock().unwrap().len();
    let stop_flag = Arc::new(AtomicBool::new(false));
    
    // Generate keys first (before starting progress tracking)
    let mode = match options.mode.as_str() {
        "ecb" => Mode::ECB,
        "gcm" => Mode::GCM,
        _ => return Err("Invalid mode".to_string()),
    };
    
    // Generate keys and handle errors
    match generate_keys_from_password(&options.password, &options.salt, mode, options.hash_with.as_str(), options.iterations) {
        Ok(_) => {},
        Err(e) => {
            // Emit verbose error message
            emit_verbose_error(&app_handle, &e);
            // Clear keys on error
            clear_keys();
            // Clear AppHandle
            *APP_HANDLE.lock().unwrap() = None;
            return Err(e);
        }
    }
    
    // Start progress tracking after successful key generation
    track_progress(app_handle.clone(), total_files, stop_flag.clone());
    
    let target_dir = options.target_path.as_ref().unwrap_or(&options.source_path);
    
    // Create directories
    if !options.dry_run {
        create_dirs(
            DIR_LIST.lock().unwrap().to_vec(),
            &options.source_path,
            target_dir,
        );
    }
    
    // Perform encryption/decryption
    match operation {
        Operation::Encrypt => {
            encrypt_files(
                FILE_LIST.lock().unwrap().to_vec(),
                options.threads,
                &options.source_path,
                target_dir,
                mode,
                options.delete_src,
                &None, // shred options
                options.anon,
                options.dry_run,
            );
        }
        Operation::Decrypt => {
            decrypt_files(
                FILE_LIST.lock().unwrap().to_vec(),
                options.threads,
                &options.source_path,
                target_dir,
                mode,
                options.delete_src,
                &None, // shred options
                options.anon,
                options.dry_run,
            );
        }
    }
    
    // Clear keys
    clear_keys();
    verify_keys_cleared(mode);
    
    let success_count = *SUCCESS_COUNT.lock().unwrap();
    let failed_count = *FAILED_COUNT.lock().unwrap();
    
    Ok(EncryptionResult {
        success: failed_count == 0,
        message: if failed_count == 0 {
            format!("Successfully {}ed {} files", options.operation, success_count)
        } else {
            format!("Completed with {} successes and {} failures", success_count, failed_count)
        },
        success_count,
        failed_count,
    })
}

#[tauri::command]
pub async fn encrypt_file(app_handle: AppHandle, options: EncryptionOptions) -> Result<EncryptionResult, String> {
    let source_file = PathBuf::from(&options.source_path);
    
    if !source_file.exists() {
        return Err("Source file does not exist".to_string());
    }
    
    *VERBOSE.write().unwrap() = options.verbose;
    
    // Set AppHandle for logger macro to emit events
    *APP_HANDLE.lock().unwrap() = Some(app_handle.clone());
    
    // Clear previous state
    DIR_LIST.lock().unwrap().clear();
    FILE_LIST.lock().unwrap().clear();
    *FILES_SIZE_BYTES.lock().unwrap() = 0;
    *SUCCESS_COUNT.lock().unwrap() = 0;
    *FAILED_COUNT.lock().unwrap() = 0;
    
    // Clear any existing keys from previous operations
    clear_keys();
    
    let mode = match options.mode.as_str() {
        "ecb" => Mode::ECB,
        "gcm" => Mode::GCM,
        _ => return Err("Invalid mode".to_string()),
    };
    
    // Generate keys and handle errors
    match generate_keys_from_password(&options.password, &options.salt, mode, options.hash_with.as_str(), options.iterations) {
        Ok(_) => {},
        Err(e) => {
            // Emit verbose error message
            emit_verbose_error(&app_handle, &e);
            // Clear keys on error
            clear_keys();
            // Clear AppHandle
            *APP_HANDLE.lock().unwrap() = None;
            return Err(e);
        }
    }
    
    let source_dir = source_file.parent().unwrap().to_str().unwrap();
    let target_dir = options.target_path.as_ref().map(|s| s.as_str()).unwrap_or(source_dir);
    
    DIR_LIST.lock().unwrap().push(PathBuf::from(target_dir));
    FILE_LIST.lock().unwrap().push(source_file.clone());
    
    let total_files = 1;
    let stop_flag = Arc::new(AtomicBool::new(false));
    
    // Start progress tracking after successful key generation
    track_progress(app_handle.clone(), total_files, stop_flag.clone());
    
    let operation = match options.operation.as_str() {
        "encrypt" => Operation::Encrypt,
        "decrypt" => Operation::Decrypt,
        _ => return Err("Invalid operation".to_string()),
    };
    
    // Create directories if needed
    if !options.dry_run {
        create_dirs(
            DIR_LIST.lock().unwrap().to_vec(),
            source_dir,
            target_dir,
        );
    }
    
    // Perform encryption/decryption
    match operation {
        Operation::Encrypt => {
            encrypt_files(
                FILE_LIST.lock().unwrap().to_vec(),
                1, // Single file, single thread
                source_dir,
                target_dir,
                mode,
                options.delete_src,
                &None,
                options.anon,
                options.dry_run,
            );
        }
        Operation::Decrypt => {
            decrypt_files(
                FILE_LIST.lock().unwrap().to_vec(),
                1, // Single file, single thread
                source_dir,
                target_dir,
                mode,
                options.delete_src,
                &None,
                options.anon,
                options.dry_run,
            );
        }
    }
    
    // Stop progress tracking
    stop_flag.store(true, Ordering::Relaxed);
    
    // Clear AppHandle
    *APP_HANDLE.lock().unwrap() = None;
    
    // Clear keys
    clear_keys();
    verify_keys_cleared(mode);
    
    let success_count = *SUCCESS_COUNT.lock().unwrap();
    let failed_count = *FAILED_COUNT.lock().unwrap();
    
    // Emit final progress update
    let final_progress = ProgressUpdate {
        current: (success_count + failed_count) as u64,
        total: total_files as u64,
        percentage: 100.0,
        message: format!("Completed: {} successful, {} failed", success_count, failed_count),
    };
    let _ = app_handle.emit("progress-update", &final_progress);
    
    Ok(EncryptionResult {
        success: failed_count == 0,
        message: if failed_count == 0 {
            format!("Successfully {}ed file", options.operation)
        } else {
            "Operation failed".to_string()
        },
        success_count,
        failed_count,
    })
}

// Helper function to emit verbose error messages
fn emit_verbose_error(app_handle: &AppHandle, message: &str) {
    use serde::{Serialize, Deserialize};
    #[derive(Serialize, Deserialize)]
    struct VerboseMsg {
        message: String,
        level: String,
    }
    let verbose_msg = VerboseMsg {
        message: message.to_string(),
        level: "error".to_string(),
    };
    let _ = app_handle.emit("verbose-message", &verbose_msg);
}

// Helper function to generate keys from password/salt directly
fn generate_keys_from_password(password: &str, salt: &str, mode: Mode, hash_with: &str, iterations: u32) -> Result<(), String> {
    use aes_gcm::Aes256Gcm;
    use aes_gcm::Key;
    use pbkdf2::pbkdf2_hmac_array;
    use sha2::Sha256;
    use zeroize::Zeroize;
    
    let hash_mode = match hash_with {
        "argon2" => HashMode::Argon2,
        "pbkdf2" => HashMode::PBKDF2,
        _ => HashMode::Argon2,
    };
    
    let mut key = match hash_mode {
        HashMode::Argon2 => {
            let mut argon2_param_builder = argon2::ParamsBuilder::new();
            let argon2_struct = match argon2_param_builder.t_cost(iterations).p_cost(4).build() {
                Ok(o) => argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, o),
                Err(e) => {
                    return Err(format!("Failed to build Argon2 parameters: {}", e));
                }
            };
            let mut key = [0u8; 32];
            match argon2_struct.hash_password_into(
                password.as_bytes(),
                salt.as_bytes(),
                &mut key,
            ) {
                Ok(_) => key,
                Err(e) => {
                    return Err(format!("Failed to generate key with Argon2ID: {}. Salt must be at least 8 bytes long.", e));
                }
            }
        },
        HashMode::PBKDF2 => {
            pbkdf2_hmac_array::<Sha256, 32>(
                password.as_bytes(),
                salt.as_bytes(),
                iterations,
            )
        },
    };
    
    let key_gen = Key::<Aes256Gcm>::clone_from_slice(key.as_slice());
    
    // Clear any existing keys before setting new ones
    match mode {
        Mode::ECB => {
            let mut ecb_keys = ECB_32BYTE_KEY.write().unwrap();
            // Zeroize all existing keys before clearing
            for existing_key in ecb_keys.iter_mut() {
                existing_key.zeroize();
            }
            ecb_keys.clear();
            ecb_keys.push(key_gen);
        }
        Mode::GCM => {
            let mut gcm_keys = GCM_32BYTE_KEY.write().unwrap();
            // Zeroize all existing keys before clearing
            for existing_key in gcm_keys.iter_mut() {
                existing_key.zeroize();
            }
            gcm_keys.clear();
            gcm_keys.push(key_gen);
        }
    }
    
    key.zeroize();
    // Note: key_gen is now owned by the vector, so we don't zeroize it here
    // It will be zeroized when clear_keys() is called
    
    Ok(())
}

#[tauri::command]
pub async fn scan_operational_info(app_handle: AppHandle, source_path: String, is_directory: bool) -> Result<(), String> {
    use human_bytes::human_bytes;
    use std::env;
    
    let path = PathBuf::from(&source_path);
    
    if !path.exists() {
        return Err("Source path does not exist".to_string());
    }
    
    // Clear previous state
    DIR_LIST.lock().unwrap().clear();
    FILE_LIST.lock().unwrap().clear();
    *FILES_SIZE_BYTES.lock().unwrap() = 0;
    
    if is_directory {
        // Same logic as encrypt_directory - add source and recurse
        DIR_LIST.lock().unwrap().push(path.clone());
        recurse_dirs(&path);
        
        let file_count = FILE_LIST.lock().unwrap().len();
        let folder_count = DIR_LIST.lock().unwrap().len().saturating_sub(1); // Subtract 1 for source directory
        let total_size_bytes = *FILES_SIZE_BYTES.lock().unwrap();
        
        let op_info = OperationalInfo {
            file_count,
            folder_count,
            total_size_bytes,
            total_size_human: human_bytes(total_size_bytes as f64),
            operating_system: env::consts::OS.to_string(),
        };
        let _ = app_handle.emit("operational-info", &op_info);
    } else {
        // Single file
        let file_size = if let Ok(metadata) = path.metadata() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                metadata.size()
            }
            #[cfg(target_os = "windows")]
            {
                metadata.file_size()
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                metadata.len()
            }
        } else {
            return Err("Failed to read file metadata".to_string());
        };
        
        let op_info = OperationalInfo {
            file_count: 1,
            folder_count: 0,
            total_size_bytes: file_size,
            total_size_human: human_bytes(file_size as f64),
            operating_system: env::consts::OS.to_string(),
        };
        let _ = app_handle.emit("operational-info", &op_info);
    }
    
    Ok(())
}

