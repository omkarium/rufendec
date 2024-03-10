## Rufendec: A Fast File Encryption Command Line tool
[![crate][crate-image]][crate-link]
![MIT licensed][license-image]
![Rust Version][rustc-image]
[![Downloads][downloads-image]][crate-link]
![Category][category-image]


Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool designed for AES-256 encryption and decryption. This tool simplifies the process of securing  the contents of a user specified source directory. Operating in ECB/GCM modes, Rufendec maintains the original file names and sub-directory structure in the target directory. Explore the simplicity of Rust for robust encryption and decryption tasks with Rufendec.

## How to Use
This is a rust binary crate, so it must be obvious that you need to treat this as an executable. If you already know what Cargo is and how to use it, then go ahead and install and `Rufendec` by running the command `cargo install rufendec`

Next, to execute rufendec try running the command `rufendec --help`. However, if you do not wish to install this program on your system permanently, then CD (change directory) into the cloned git repo and run `cargo run -- --help`.

Either way, the result of executing Rufendec will be like the below.


```
Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool designed for AES-256 encryption and decryption. This tool simplifies the process of securing  the contents of a user specified source directory. Operating in ECB/GCM modes, Rufendec maintains the original file names and sub-directory structure in the target directory. Explore the simplicity of Rust for robust encryption and decryption tasks with Rufendec.

Usage: rufendec [OPTIONS] --password-file <PASSWORD_FILE> --operation <OPERATION> --mode <MODE> <SOURCE_DIR> <TARGET_DIR>

Arguments:
<SOURCE_DIR>  Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
<TARGET_DIR>  Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go)

Options:
-p, --password-file <PASSWORD_FILE>    Enter the Filename containing your password (and the "salt" in the 2nd line if you choose gcm) here. This is used to either Encrypt or Decrypt the Source Dir files
-o, --operation <OPERATION>            Enter the Operation you want to perform on the Source Dir using the password you provided [possible values: encrypt, decrypt]
-t, --threads <THREADS>                Threads to speed up the execution [default: 8]
-m, --mode <MODE>                      Provide the mode of Encryption here [possible values: ecb, gcm]
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
In the above examples, the names `source-dir` and `target-dir` are arbitrary. You can use any names to your source and target directories. The target directory is something which is always created if not created already.

*Also, when you choose GCM mode, in the password file, you have to pass a salt in the 2nd line after specifying the password in th 1st line. But if you go for ECB mode, you don't need to specify a salt. In either case, the password and salt can be of any arbitrary length because the key generation in the program is happening via PBKDF2*

Example context inside a ./passwordfile
```
Som3RandPa$$wdOfAnyLength
SomethingSaltIGiveOfAnyLength
```
---------------------------------------

### ⚠️ Warning ⚠️

Using this program MUST be considered DANGEROUS. Since this is a file encryption software, there is a possibility that you could lose your data forever if used incorrectly. I strongly suggest you to use it on a test folder first with the files you want to encrypt and later try to decrypt and see if the file content is still the same by comparing their checksum. Do note that for file types such as pdf, the checksum may not be the same as the metadata such as creation time, modified time changes. 

Kindly take backup of whatever you are encrypt first. I repeat, BACKUP BACKUP BACKUP!!! as frequent as you can.

If you find any security vulnerabilities in code, please submit an issue.

---------------------------------------
Three critical points before you use this
---------------------------------------

1. Make sure you are not decrypting a source folder which is not already encrypted. If done so, your source files WILL get corrupted.
   This program WILL not be able to pre-validate whether the files you have provided as input are either encrypted or decrypted. 

2. This program refuses to encrypt those kind of files which are not utf-8 compatible, for example binary files/executables.
   It will either create or skip such files, but ensure you don't try to encrypt anything as such in the first place.
   If done so, the later you decrypt them, the binaries may or may not work.

3. If you have encrypted files with --mode=gcm, and you tried to decrypt with --mode=ecb, 
  then the program will generate your decrypted target files, but those WILL get corrupted filled with gibberish.

Ensure you provide the correct files for the operation you choose

USE AT YOUR OWN RISK!

### Will I maintain this project?

I am just a Rust amateur, and I tend to forget what I have learnt even after writing complex stuff and spending days on it if I just take a few months break from coding. So, if any problem arises with this tool, I might not be able to immediately fix it or add a new feature, but I will try to support this to the best of my abilities and interest. I also believe that tools like these are one-off, like "Write once, compile and execute anywhere". This is not that kind of tool which needs constant maintenance. It only has to be maintained only if the Dependent crates in Cargo.toml change versions, and yank the older versions. But that is very unlikely to happen. Even so, you can always find a compiled release here on github releases.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/rufendec.svg
[crate-link]: https://crates.io/crates/rufendec
[license-image]: https://img.shields.io/badge/License-MIT-yellow.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.75+-blue.svg
[downloads-image]: https://img.shields.io/crates/d/rufendec.svg
[category-image]: https://img.shields.io/badge/category-File_encryption_software-darkred.svg