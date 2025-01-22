## Rufendec: A Fast File Encryption Command Line tool
[![crate][crate-image]][crate-link]
![MIT licensed][license-image]
![Rust Version][rustc-image]
[![Downloads][downloads-image]][crate-link]
![Category][category-image]


Rufendec (The Rust File Encryptor-Decryptor) is a lightweight CLI tool for AES-256 encryption and decryption, preserving file names and directory structure. With support for ECB/GCM modes, it simplifies securing and restoring files with ease, all powered by Rust.

### Use cases
- Encrypt your files and retain the directory structure, so you can upload to a cloud storage for backup. This is especially useful when your backup medium does not support FDE. Moreover, you can target a particular file(s) or folder(s) for decryption from your backup.
- Unlike FDE's like LUKS and Bitlocker which does block level encryption, files won't get corrupted as this is file level encryption.

### Features
- Encrypt and decrypt multiple files when operating on the directory level using AES-256 GCM and ECB modes. GCM is chosen as the default mode.
- Encrypt and decrypt a single file.
- Suppress all terminal I/O while working on a single file.
- The program is multi-threaded, so the user can manually choose the number of threads.
- The password file with ".omk" extension can be maintained in /etc, /home, /root or even the current directory (".") if you are a linux user. For windows, the file can be placed either in the current directory or "C:/WINDOWS/SYSTEM32/config"
- PBKDF2-HMAC-SHA256 is used for the key derivation. The default iterations the program use is 60000
- Encrypted files can be observed with a ".enom" extension, so you can distinguish between encrypted and normal files.
- Program refuse to encrypt already encrypted source files (with ".enom extension") as a safe guard mechanism by preventing double encryption (But is won't work when using file-level encryption).
- Prevents accidentally encrypting directories such as /, /etc, /bin, /sbin etc. We have totally 23 illegal locations defined in the program.
- In-place file encryption and decryption is possible if the target directory is not specified as a Command line argument, but use in conjunction with "-d" option.
- Source files can be deleted by passing the "-d" option.
- Verbose output using "-v" option.

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

Usage: rufendec dir [OPTIONS] --operation <OPERATION> <SOURCE_DIR> [TARGET_DIR]

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
  -i, --iterations <ITERATIONS>        Iterations for PBKDF2 [default: 60000]
  -v, --verbose                        Print verbose output
  -h, --help                           Print help
```

For `rufendec file --help`

```
Targets on the file level

Usage: rufendec file [OPTIONS] --operation <OPERATION> <SOURCE_FILE> [TARGET_DIR]

Arguments:
  <SOURCE_FILE>  Specify the Source file here (This is the file you want to either Encrypt or Decrypt)
  [TARGET_DIR]   Specify the Target directory here. But if you do not provide this, the target file will be placed in the source file's Directory

Options:
  -f, --password-file <PASSWORD_FILE>  Specify the password file with an extension ".omk". The first line in the file must have the password, and the second line must have the salt
  -k, --skip-passwd-file-search        Skip the password_file search on the machine in case you decided to not provide the `password_file` in the CLI options
  -p, --passwd <PASSWD>                Specify the password (in case `password_file` is not provided and `supress_terminal` is set to true)
  -s, --salt <SALT>                    Specify the salt (in case `password_file` is not provided and `supress_terminal` is set to true)
  -o, --operation <OPERATION>          Specify the Operation you want to perform on the Source file [possible values: encrypt, decrypt]
  -m, --mode <MODE>                    Provide the mode of Encryption here [default: gcm] [possible values: ecb, gcm]
  -d, --delete-src                     Pass this option to delete the source file
  -i, --iterations <ITERATIONS>        Iterations for PBKDF2 [default: 60000]
  -z, --supress-terminal               Supress all CLI output
  -v, --verbose                        Print verbose output
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

rufendec dir ./source-dir ./target-dir -f ./passwordfile -o encrypt -m gcm -t 12 -i 100000

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

To decrypt a source file and place it in the same source directory, but deleting the source file, and to skip the password file search on the machine and provide the password and salt as CLI options
```
rufendec file -o decrypt ../source-file -d -k -p [YOUR_PASSWORD] -s [YOUR_SALT]
```

To decrypt a source file and place it in the same source directory, but deleting the source file, and to skip the password file search on the machine and provide the password and salt as CLI options, and supress all terminal Input output. Note: while using `-z` you must use `-p` and `-s`, or atleast do not use `-k`. This mean using `-kz` without `-p` and `-s` won't work.
```
rufendec file -o decrypt ../source-file -p [YOUR_PASSWORD] -s [YOUR_SALT] -dkz
```

*Note: In the password file, you have to specify the password in th 1st line and the salt in the second line. The password and salt can be of any arbitrary length because the key generation in the program is happening via PBKDF2*

Example context inside a ./passwordfile
```
Som3RandPa$$wdOfAnyLength
SomethingSaltIGiveOfAnyLength
```
---------------------------------------

### In-Place Encryption and Decryption

If you do not wish to create a separate target directory whether it is to place the encrypted or decrypted files, then you should not pass the [TARGET_DIR] argument in the command line. Along with that, you must send the `-d` option to delete the source files in the <SOURCE_DIR>, otherwise both the source and target files would end up in the same source directory. 

But beware that delete only removes the links of inodes from your filesystem. The source files could still exist on your device. Hence, it is recommended to not use the delete option, and shred the source files using programs like 'shred' in linux separately. However, if your device is an SSD, due to the nature of SSD's having extra sectors than listed for redundancy, some of your files could creep into sectors which are considered dead and your OS cannot touch or be aware of such bad/illegal sectors, so shred may not truly delete the file. Hence, it is adviced to use HDDs to store and wipe data. Some SSD's also come with secure wipe provided by the manfucturer. If security is a MUST for you, then its better to go with FDE.

--------------------------------------

### Illegal locations (Do not use them as your source directory)
"/", "/root", "/home", "/boot", "/usr", "/lib", "/lib64", "/lib32", "/libx32", "/mnt", "/dev", "/sys", "/run", "/bin", "/sbin", "/proc", "/media", "/var", "/etc", "/srv", "/opt", "C:", "c:"

--------------------------------------

### ⚠️ Warning ⚠️

Note: The same warning message would be displayed on the console when you are operating on directory-level using `rufendec dir [...]`, but not while operating on file-level

Using this program MUST be considered DANGEROUS. Since this is a file encryption software, there is a possibility that you could lose your data forever if used incorrectly. I strongly suggest you to use it on a test folder first with the files you want to encrypt and later try to decrypt and see if the file content is still the same by comparing their checksum. Do note that for file types such as pdf, the checksum may not be the same as the metadata such as creation time, modified time changes. 

Kindly take backup of whatever you are encrypt first. I repeat, BACKUP BACKUP BACKUP!!! as frequent as you can.

If you find any security vulnerabilities in code, please submit an issue privately.

-----------------
Rules to follow
-----------------

1. Make sure you are not trying to decrypt unencrypted files or encrypt already encrypted files.
Avoid using too many threads while processing large files. For example, say you have 10 files of each 1 GB and you are using 10 threads at once, then 10 GB of memory could be consumed.

2. It is recommended to not encrypt utf-8 incompatible files, for example binary files/executables.
It will either create or skip such files, but ensure you don't try to encrypt anything as such in the first place. If done so, the later you decrypt them, the binaries may or may not work.

3. If you have encrypted files with --mode=gcm, and you tried to decrypt with --mode=ecb, 
  then the program will generate your decrypted target files, but those WILL get corrupted filled with gibberish.

4. If you have characters other than Alphanumeric (spaces are fine) in your folder and file names, then do not use them with this program. The program does not refuse to work with them, but your files will be misplaced in weird locations because you had weird characters in your file and folder names.

5. If you did not specify a target directory, then make sure you don't stop the process in between. 
   Allow the operation to fully complete.

Ensure you provide the correct files for the operation you choose. Do some dummy tests before using on important files

USE AT YOUR OWN RISK!

---------------------------------------
### Does this software require maintenance?

Yes. This software do require maintenance, but only in two cases. 

1. If the Dependent crates in Cargo.toml change versions, and the authors yank the older versions. But that is very unlikely to happen. Even so, you can always find a compiled release here on github releases.
2. If someone finds a bug and reports it.

-----------------------------
### Benchmark Test (old test)

CPU: Intel i5 (4cores) @ 3.300GHz

GPU: Intel 2nd Generation Core Processor Family

RAM: 11835 MiB

Linux Mint 21.1 X86_64

Target folders created : 1431

Target files created: 6435

Source Folder Size: 1.6 GiB

Encryption took 13 seconds at the rate of 123 MiB/sec

Decryption took 11 seconds at the rate of 145.5 MiB/sec

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