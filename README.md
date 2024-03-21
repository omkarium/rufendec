## Rufendec: A Fast File Encryption Command Line tool
[![crate][crate-image]][crate-link]
![MIT licensed][license-image]
![Rust Version][rustc-image]
[![Downloads][downloads-image]][crate-link]
![Category][category-image]


Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool designed for AES-256 encryption and decryption. This tool simplifies the process of securing  the contents of a user specified source directory. Operating in ECB/GCM modes, Rufendec maintains the original file names and sub-directory structure in the target directory. Explore the simplicity of Rust for robust encryption and decryption tasks with Rufendec.

### Features
- Encrypt and decrypt multiple files using AES-256 GCM mode. GCM is chosen as the default mode.
- The program is multi-threaded, so the user can manually choose the number of threads.
- The password file with ".omk" extension can be maintained in /etc, /home, /root or even the current directory (".") if you are a linux user. For windows, the file can be placed either in the current directory or "C:/WINDOWS/SYSTEM32/config"
- PBKDF2-HMAC-SHA256 is used for the key derivation. The default iterations the program use is 60000
- Program refuse to encrypt already encrypted source files as a safe guard mechanism from double encryption.
- In place file encryption and decryption is possible if the target directory is not specified as a Command line argument.
- Source files can be deleted by passing the "-d" option.

## How to Use
This is a rust binary crate, so it must be obvious that you need to treat this as an executable. If you already know what Cargo is and how to use it, then go ahead and install and `Rufendec` by running the command `cargo install rufendec`

If you have the executable/binary file then try running the program using the command `rufendec --help`. However, if you do not wish to install this program on your system permanently, then CD (change directory) into the cloned git repo and run `cargo run -- --help`.

Either way, the result of executing Rufendec will be something similar to the below.


```
Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool designed for AES-256 encryption and decryption. This tool simplifies the process of securing  the contents of a user specified source directory. Operating in ECB/GCM modes, Rufendec maintains the original file names and sub-directory structure in the target directory. Explore the simplicity of Rust for robust encryption and decryption tasks with Rufendec.

Usage: rufendec [OPTIONS] --operation <OPERATION> <SOURCE_DIR> [TARGET_DIR]

Arguments:
<SOURCE_DIR>  Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
[TARGET_DIR]  Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go). But if you do not provide this, the target files will be placed in the Source Dir. To delete the source files make sure you pass option -d


Options:
-d, --delete-src                       Pass this option to delete the source files in the Source Dir
-p, --password-file <PASSWORD_FILE>    Enter the password file with an extension ".omk". The first line in the file must have the password, and If you choose mode=gcm then ensure to pass the "Salt" in the 2nd line [default: ]
-o, --operation <OPERATION>            Enter the Operation you want to perform on the Source Dir [possible values: encrypt, decrypt]
-t, --threads <THREADS>                Threads to speed up the execution [default: 8]
-m, --mode <MODE>                      Provide the mode of Encryption here [default: gcm] [possible values: ecb, gcm]
-i, --iterations <ITERATIONS>          Iterations --mode=gcm [default: 60000]
-h, --help                             Print help
-V, --version                          Print version
```

### Demo
<img src="https://github.com/omkarium/gifs/blob/main/encrypt-and-decrypt-using-gcm.gif" alt="Rufendec Demo gif" title="Rufendec Demo gif" width="850"/>

### How to Encrypt
To illustrate how to use this, say you want to encrypt all the files in the directory `./source-dir` using a password. An example password would be like **Thisi/MyKeyT0Encryp**, which is maintained in a password file. Now you want all the files in this "./source-dir" encrypted and have them placed in a target directory say `./target-dir` by **retaining the complete file names and sub-directory structure of the source inside**. Then you can run the command like this

```
cargo run ../source-dir ../target-dir --password-file=../passwordfile --operation=encrypt --mode=ecb
```
or
```
rufendec ./source-dir ./target-dir --password-file=./passwordfile --operation=encrypt --mode=ecb
```

Here are some variations in the command

```
rufendec ./source-dir ./target-dir --password-file ./passwordfile --operation encrypt --mode ecb

OR

rufendec ./source-dir ./target-dir -p ./passwordfile -o encrypt -m gcm -t 12 -i 100000

OR

rufendec ./source-dir ./target-dir -o encrypt

OR

rufendec ./source-dir -o encrypt

```
The mode, threads and iterations have default values, so you do not need to pass them. Also, if you maintain the password file in /etc, /home, /root, ".", "..", "../../", then you do not need to pass the -p option.

If you do not pass options like -m, -t, -i then the default values will be chosen.

### How to Decrypt
Now imagine you have deleted the directory "source-dir" after successfully encrypting the files, but now you want the decrypted files and their respective parent directories and the structure back.

To decrypt the encrypted files inside the "target-dir" you currently have with you, just run the below command. Once finished, your original files will be back in your source-dir.
```
cargo run ../target-dir ../source-dir --password-file=../passwordfile --operation=decrypt --mode=ecb
```
or
```
rufendec ./target-dir ./source-dir --password-file=./passwordfile --operation=decrypt --mode=ecb
```
In the above examples, the names `source-dir` and `target-dir` are arbitrary. You can use any names to your source and target directories. The target directory is created if not created already.

---

*Also, when you choose GCM mode, in the password file, you have to pass a salt in the 2nd line after specifying the password in th 1st line. But if you go for ECB mode, you don't need to specify a salt. In either case, the password and salt can be of any arbitrary length because the key generation in the program is happening via PBKDF2*

Example context inside a ./passwordfile
```
Som3RandPa$$wdOfAnyLength
SomethingSaltIGiveOfAnyLength
```
---------------------------------------

### In-Place Encryption and Decryption

If you do not wish to create a separate target directory whether it is to place the encrypted or decrypted files, then you should not pass the [TARGET_DIR] argument in the command line. Along with that, you must send the `-d` option to delete the source files in the <SOURCE_DIR>

--------------------------------------

### ⚠️ Warning ⚠️

Using this program MUST be considered DANGEROUS. Since this is a file encryption software, there is a possibility that you could lose your data forever if used incorrectly. I strongly suggest you to use it on a test folder first with the files you want to encrypt and later try to decrypt and see if the file content is still the same by comparing their checksum. Do note that for file types such as pdf, the checksum may not be the same as the metadata such as creation time, modified time changes. 

Kindly take backup of whatever you are encrypt first. I repeat, BACKUP BACKUP BACKUP!!! as frequent as you can.

If you find any security vulnerabilities in code, please submit an issue privately.

---------------------------------------
Four unbreakable rules you MUST follow
---------------------------------------

1. Make sure you are not trying to decrypt unencrypted files or encrypt already encrypted files.

2. This program refuses to encrypt those kind of files which are not utf-8 compatible, for example binary files/executables.
   It will either create or skip such files, but ensure you don't try to encrypt anything as such in the first place.
   If done so, the later you decrypt them, the binaries may or may not work.

3. If you have encrypted files with --mode=gcm, and you tried to decrypt with --mode=ecb, 
  then the program will generate your decrypted target files, but those WILL get corrupted filled with gibberish.

4. If you have characters other than Alphanumeric (spaces are fine) in your folder and file names, then do not use them with this program. The program does not refuse to work with them, but your files will be misplaced in weird locations because you had weird characters in your file and folder names.

Ensure you provide the correct files for the operation you choose

USE AT YOUR OWN RISK!

---------------------------------------
### Does this software require maintenance?

Yes. This software do require maintenance, but only in two cases. 

1. If the Dependent crates in Cargo.toml change versions, and the authors yank the older versions. But that is very unlikely to happen. Even so, you can always find a compiled release here on github releases.
2. If someone finds a bug and reports it.


[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/rufendec.svg
[crate-link]: https://crates.io/crates/rufendec
[license-image]: https://img.shields.io/badge/License-MIT_or_Apache_2.0-yellow.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.75+-blue.svg
[downloads-image]: https://img.shields.io/crates/d/rufendec.svg
[category-image]: https://img.shields.io/badge/category-File_encryption_software-darkred.svg
