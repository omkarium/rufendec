## Rufendec: A Fast File Encryption Command Line tool
[![crate][crate-image]][crate-link]
![MIT licensed][license-image]
![Rust Version][rustc-image]
[![Downloads][downloads-image]][crate-link]
![Category][category-image]


Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool for AES-256 encryption and decryption, preserving file names and directory structure. With support for ECB/GCM modes, it simplifies securing and restoring files with ease, all powered by Rust.

### Use Case
- <ins>**Encrypt files while preserving directory structure**</ins>: This allows you to upload encrypted files to cloud storage for backup. It's especially useful when your backup medium doesn’t support Full Disk Encryption (FDE). Additionally, it enables you to target specific files or folders for decryption from the backup, providing greater flexibility.

- <ins>**File-level encryption vs. block-level encryption**</ins>: Unlike Full Disk Encryption solutions like LUKS or BitLocker, which encrypt at the block level and can suffer from potential issues like sector header corruption, this tool performs file-level encryption. This minimizes the risk of file corruption and ensures that only the encrypted files are affected, not the entire disk.

- <ins>**Use on embedded devices or mobile platforms**</ins>: This tool is particularly useful for encrypting files on embedded devices or mobile platforms where Full Disk Encryption (FDE) may not be supported. These devices often have limited resources, or their operating systems may not support full disk encryption, making file-level encryption an ideal solution for securing sensitive data without requiring FDE.

### Features
- Encrypt and decrypt multiple files when operating on the directory level using AES-256 GCM and ECB modes. GCM is chosen as the default mode.
- Encrypt and decrypt a single file.
- Suppress all terminal I/O while working on a single file.
- The program is multi-threaded, so the user can manually choose the number of threads.
- The password file with ".omk" extension can be maintained in /etc, /home, /root or even the current directory (".") if you are a linux user. For windows, the file can be placed either in the current directory or "C:/WINDOWS/SYSTEM32/config"
- Argon2ID and PBKDF2-HMAC-SHA256 can be used for the key derivation. Argon2 is used by default and the default iterations is 10
- Encrypted files can be observed with a ".enom" extension, so you can distinguish between encrypted and normal files.
- Program refuse to encrypt already encrypted source files (with ".enom extension") as a safe guard mechanism by preventing double encryption (But is won't work when using file-level encryption).
- Prevents accidentally encrypting directories such as /, /etc, /bin, /sbin etc. We have totally 23 illegal locations defined in the program.
- In-place file encryption and decryption is possible if the target directory is not specified as a Command line argument, but use in conjunction with "-d" option.
- Source files can be deleted by passing the "-d" option.
- Shred the source files instead of delete.
- Verbose output using "-v" option.
- Anonymize source file names using "-a" option.
- Dry run feature using "-r" option ("-d" will be automatically ignored while using this).

## How to Use
``Method 1``: This is a rust binary crate, so treat it as an executable. If you already know what Cargo is, how to install and use it, then go ahead and install by running the command `cargo install rufendec`. However, if you do not wish to install this program on your system permanently, then CD (change directory) into the cloned git repo and run `cargo run -- --help`.

`Method 2`: If you download the executable/binary file taken from the release files in the github repo (which is the easiest method), then try running the program using the command `./rufendec --help` in the folder where the executable is located. 

Either way, the result of executing Rufendec will be something similar to the below.


```
Rufendec is a lightweight CLI tool for AES-256 encryption and decryption, preserving file names and directory structure. With support for ECB/GCM modes, it simplifies securing and restoring files with ease, all powered by Rust.

Usage: rufendec <COMMAND>

Commands:
  dir   Targets on the directory/folder level
  file  Targets on the file level
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

As the Commands imply, `dir` is used when you want to encrypt or decrypt files which are under a specified directory.
`file` is used when you want to operate on individual files.

for more info try `rufendec dir --help` and `rufendec file --help`

The result would be as follows.

For `rufendec dir --help`

```
Targets on the directory/folder level

Usage: rufendec dir [OPTIONS] --operation <OPERATION> <SOURCE_DIR> [TARGET_DIR] [COMMAND]

Commands:
  shred  Shreds the source files
  help   Print this message or the help of the given subcommand(s)

Arguments:
  <SOURCE_DIR>  Specify the Source Directory here
  [TARGET_DIR]  Specify the Target Directory here. But if you do not provide this, the target files will be placed in the Source Directory

Options:
  -f, --password-file <PASSWORD_FILE>  Specify the password file with an extension ".omk". The first line in the file must have the password, and the second line must have the salt
  -k, --skip-passwd-file-search        Skip the password_file search on the machine in case you decided to not provide the password_file in the CLI options
  -o, --operation <OPERATION>          Specify the Operation you want to perform on the Source Directory [possible values: encrypt, decrypt]
  -m, --mode <MODE>                    Provide the mode of Encryption here [default: gcm] [possible values: ecb, gcm]
  -d, --delete-src                     Pass this option to delete the source files in the Source Directory
  -t, --threads <THREADS>              Threads to speed up the execution [default: 8]
  -x, --hash-with <HASH_WITH>          Generate the secure key with the specified hashing function algorithm [default: argon2] [possible values: argon2, pbkdf2]
  -i, --iterations <ITERATIONS>        Iterations for the choosen hashing function [default: 10]
  -v, --verbose                        Print verbose output
  -r, --dry-run                        Skip all file creation and deletion
  -a, --anon                           Anonymize source file names
  -h, --help                           Print help
```

For `rufendec file --help`

```
Targets on the file level

Usage: rufendec file [OPTIONS] --operation <OPERATION> <SOURCE_FILE> [TARGET_DIR] [COMMAND]

Commands:
  shred  Shreds the source files
  help   Print this message or the help of the given subcommand(s)

Arguments:
  <SOURCE_FILE>  Specify the Source file here (This is the file you want to either Encrypt or Decrypt)
  [TARGET_DIR]   Specify the Target directory here. But if you do not provide this, the target file will be placed in the source file's Directory

Options:
  -f, --password-file <PASSWORD_FILE>  Specify the password file with an extension ".omk". The first line in the file must have the password, and the second line must have the salt
  -k, --skip-passwd-file-search        Skip the password_file search on the machine in case you decided to not provide the `password_file` in the CLI options
  -p, --passwd <PASSWD>                Specify the password (in case `password_file` is not provided and `suppress_terminal` is set to true)
  -s, --salt <SALT>                    Specify the salt (in case `password_file` is not provided and `suppress_terminal` is set to true)
  -o, --operation <OPERATION>          Specify the Operation you want to perform on the Source file [possible values: encrypt, decrypt]
  -m, --mode <MODE>                    Provide the mode of Encryption here [default: gcm] [possible values: ecb, gcm]
  -d, --delete-src                     Pass this option to delete the source file
  -x, --hash-with <HASH_WITH>          Generate the secure key with the specified hashing function algorithm [default: argon2] [possible values: argon2, pbkdf2]
  -i, --iterations <ITERATIONS>        Iterations for the choosen hashing function [default: 10]
  -z, --suppress-terminal              Suppress all CLI output
  -v, --verbose                        Print verbose output
  -r, --dry-run                        Skip all file creation and deletion
  -a, --anon                           Anonymize source file name
  -h, --help                           Print help
```

### How to Encrypt (Directory level)
To illustrate how to use this, say you want to encrypt all the files in the directory `./source-dir` using a password and salt. An example password would be like **Thisi/MyKeyT0Encryp** and salt **SOmthing#$2** in the second line, which is maintained in a password file. Now you want all the files in this "./source-dir" encrypted and have them placed in a target directory say `./target-dir` by **retaining the complete file names and sub-directory structure of the source inside**. Then you can run the command like this

```
cargo run -- dir ../source-dir ../target-dir --password-file=../passwordfile --operation=encrypt --mode=ecb
```
or
```
rufendec dir ./source-dir ./target-dir --password-file=./passwordfile --operation=encrypt --mode=ecb
```

Here are some variations in the command

```
rufendec dir ./source-dir ./target-dir --password-file ./passwordfile --operation encrypt --mode ecb

OR

rufendec dir ./source-dir ./target-dir -f ./passwordfile -o encrypt -m gcm -t 12 -i 100000 -m pbkdf2

OR

rufendec dir ./source-dir ./target-dir -o encrypt

OR

rufendec dir ./source-dir -o encrypt

```
The mode, threads and iterations have default values, so you do not need to pass them. 

Also, if you maintain the password file (with ".omk" extension) in /etc, /home, /root, ".", "..", "../../", then you do not need to pass the `-f` option. But if you do decided to not use `-f`, then it can take time to find your password file on your machine depending on where you placed it. If you decided to neither look for a password file nor use the `-f` option, then use the `-k` option to manually enter the password and the salt when prompted.


### How to Decrypt (Directory level)
Now imagine you have deleted the directory "source-dir" after successfully encrypting the files, but now you want the decrypted files and their respective parent directories and the structure back.

To decrypt the encrypted files inside the "target-dir" you currently have with you, just run the below command. Once finished, your original files will be back in your source-dir.
```
cargo run -- dir ../target-dir ../source-dir --password-file=../passwordfile --operation=decrypt --mode=ecb
```
or
```
rufendec dir ./target-dir ./source-dir --password-file=./passwordfile --operation=decrypt --mode=ecb
```
In the above examples, the names `source-dir` and `target-dir` are arbitrary. You can use any names to your source and target directories. The target directory is created if not created already.

---

### How to use `file` subcommands
Everything which is explained above is applicable when you use `rufendec dir [...]` command. Similarly, you can choose to only operate on single files using `rufendec file [...]` command. You can use other options such as `-i`, `-m` like you did with directories. Except `-t` won't work because a single file only needs a single thread.

To encrypt a source file and place it in a target directory, and using a password-file
```
rufendec file -o encrypt ../source-file ../target-directory -f ./password-file
```

To encrypt a source file and place it in the same source directory, and using a password-file
```
rufendec file -o encrypt ../source-file -f ./password-file
```

To encrypt a source file and place it in the same source directory, but delete the source file, and using a password-file
```
rufendec file -o encrypt ../source-file -d -f ./password-file
```

To encrypt a source file and place it in the same source directory, but to seach for a password file on the machine. If not the file is not found then the program will prompt to enter the password and salt manually.
```
rufendec file -o encrypt ../source-file
```

To decrypt a source file and place it in the same source directory, without deleting the source file, but to skip the password file search on the machine and manually enter the password and salt
```
rufendec file -o decrypt ../source-file -k
```

To decrypt a source file and place it in the same source directory, but delete the source file, and to skip the password file search on the machine and provide the password and salt as CLI options
```
rufendec file -o decrypt ../source-file -d -k -p [YOUR_PASSWORD] -s [YOUR_SALT]
```

To decrypt a source file and place it in the same source directory, but delete the source file, and to skip the password file search on the machine and provide the password and salt as CLI options, and suppress all terminal Input output. Note: while using `-z` you must use `-p` and `-s`, or atleast do not use `-k`. This mean using `-kz` without `-p` and `-s` won't work.
```
rufendec file -o decrypt ../source-file -p [YOUR_PASSWORD] -s [YOUR_SALT] -dkz
```

*Note: In the password file, you have to specify the password in th 1st line and the salt in the second line. The password and salt can be of any arbitrary length because the key generation in the program is happening via Argon2 or PBKDF2*

Example context inside a ./passwordfile
```
Som3RandPa$$wdOfAnyLength
SomethingSaltIGiveOfAnyLength
```
---------------------------------------

### In-Place Encryption and Decryption

If you do not wish to create a separate target directory whether it is to place the encrypted or decrypted files, then you should not pass the [TARGET_DIR] argument in the command line. Along with that, you must send the `-d` option to delete the source files in the <SOURCE_DIR>, otherwise both the source and target files would end up in the same source directory. 

Note: `-d` will be ignored if `shred` subcommand is used which is explained in the next section.

#### Important Considerations on Deleting and Shredding Files:

When you delete files, it typically only removes the links to the inodes in the filesystem, but the actual data may still exist on your device. For better security, it's recommended not to rely on the delete option alone. Instead, you should use tools like shred (on Linux) to securely overwrite and remove the source files. However, if your device is an SSD, there are additional considerations. Due to the nature of SSDs, which have extra sectors for redundancy, some data might be written to sectors that are considered “bad” or “dead.” These sectors cannot be accessed or recognized by your operating system, meaning the data could persist beyond your control, and shred may not fully erase it.

As a result, it is generally recommended to use HDDs for secure storage and wiping of sensitive data. Additionally, frequent shredding on SSDs is not ideal, as it can wear out the drive more quickly. Some SSDs come with a built-in secure wipe feature provided by the manufacturer, which can be a better option for securely erasing data. However, if data security is a top priority, Full Disk Encryption (FDE) is still the most reliable method for ensuring that your data remains secure.

Moreover, using the `-d` option is much faster in performance than `shred`.

### Source File Shred SubCommand

Rufendec comes with a basic `shred` subcommand available for both `dir` and `file` commands. Use this feature if you do not just want to delete the source files but shred them instead. The way this works is, the program overwrites the source files data over multiple iterations and also rename them several times before deleting. So shred is more like 

overwrite * (n) + rename * (n) + delete. 

where n is the number of iterations.

try `rufendec dir shred --help` and `rufendec file shred --help`

Also, shred comes with defaults if you use it, but if you don't use it, nothing would happen to your source files.

### Anonymize feature

Rufendec includes an Anonymize Filename feature. When you use the -a option with the dir or file subcommands to encrypt files, the program generates random filenames for the target files using a random name generator.

To decrypt the anonymized files, you must also use the -a option. If you don't, the decrypted files will be corrupted.

This happens because the original file names and paths are preserved by appending them to the content of the source files before encryption. During decryption, the program decrypts the content as usual, but then retrieves the original file names from the file content, replaces the original file path with the target file path, and recreates the target files accordingly.


--------------------------------------

### Illegal locations (Do not use them as your source directory)
"/", "/root", "/home", "/boot", "/usr", "/lib", "/lib64", "/lib32", "/libx32", "/mnt", "/dev", "/sys", "/run", "/bin", "/sbin", "/proc", "/media", "/var", "/etc", "/srv", "/opt", "C:", "c:"

--------------------------------------

### ⚠️ Warning ⚠️

Note: The same warning message would be displayed on the console when you are operating on directory-level using `rufendec dir [...]`, but not while operating on file-level

Using this program MUST be considered DANGEROUS. Since this is a file encryption software, there is a possibility that you could lose your data forever if used incorrectly. I strongly suggest you to use it on a test folder first with the files you want to encrypt and later try to decrypt and see if the file content is still the same by comparing their checksum. Do note that for file types such as pdf, the checksum may not be the same as the metadata such as creation time, modified time changes. 

Kindly take backup of whatever you are encrypt first. I repeat, BACKUP BACKUP BACKUP!!! as frequent as you can.

If you find any security vulnerabilities in code, please submit an issue privately.

---------------
Rules to Follow
---------------
1. Avoid Decrypting Unencrypted Files or Encrypting Already Encrypted Files: Make sure you're not attempting to decrypt files that haven't been encrypted, or encrypt files that are already encrypted.

2. Limit Threads for Large Files: When processing large files, avoid using too many threads. For instance, if you have 10 files of 1 GB each and are using 10 threads simultaneously, your system could use up to 10 GB of memory.

3. Do Not Encrypt UTF-8 Incompatible Files: It's recommended to avoid encrypting files that aren't compatible with UTF-8, such as binary files or executables. The tool may either skip or create such files, but if encrypted, they may not function properly when decrypted. Always avoid encrypting such files in the first place.

4. Avoid Special Characters in File and Folder Names: If your file or folder names contain characters other than alphanumeric ones (spaces are fine), do not use them with this program. While the program won’t prevent you from using them, your files may be misplaced in unexpected locations due to these characters.

5. Do Not Interrupt the Process: If you haven't specified a target directory, do not interrupt the process mid-way. Allow the operation to complete fully to avoid any issues with your files.

6. Perform Test Runs Before Using on Important Files: Always ensure that you're providing the correct files for the operation. Run some test cases on dummy files before using the tool on important data to avoid errors.

USE AT YOUR OWN RISK!

---------------------------------------
### Does this software require maintenance?

Yes. This software do require maintenance, but only in two cases. 

1. If the Dependent crates in Cargo.toml change versions, and the authors yank the older versions. But that is very unlikely to happen. Even so, you can always find a compiled release here on github ![releases](https://github.com/omkarium/rufendec/releases).
2. If someone finds a bug and reports it.

------------------------
### Demo (This demo is for an old version <=0.7.0)
<img src="https://github.com/omkarium/gifs/blob/main/encrypt-and-decrypt-using-gcm.gif" alt="Rufendec Demo gif" title="Rufendec Demo gif" width="850"/>


[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/rufendec.svg
[crate-link]: https://crates.io/crates/rufendec
[license-image]: https://img.shields.io/badge/License-MIT_or_Apache_2.0-yellow.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.75+-blue.svg
[downloads-image]: https://img.shields.io/crates/d/rufendec.svg
[category-image]: https://img.shields.io/badge/category-File_encryption_software-darkred.svg
