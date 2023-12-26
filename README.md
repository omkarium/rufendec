Rufendec aka (Rust File Encryptor-Decryptor) is a CLI utility tool which helps you to do AES-256 Encryption and Decryption on specified directories/folders
and retain the complete directory structure of the source directory files you provide into the target directory.

## How to Use
This is a binary crate, so its obvious that you need to use this as an executable. 
First have cargo install and then run `cargo install rufendec`
Next, go to the location of the binary and run the executable

### Example
If you run cargo run -- --help or ./rufendec --help. You will get this response

```
Rufendec aka (Rust File Encryptor-Decryptor) is a CLI utility tool which helps you to do AES-256 Encryption and Decryption on specified directories/folders and retain the complete directory structure of the source directory files you provide into the target directory.

Usage: rufendec [OPTIONS] --key-file <KEY_FILE> --operation <OPERATION> <SOURCE_DIR> <TARGET_DIR>

Arguments:
<SOURCE_DIR>  Enter the Source Dir here (This is the directory you want to either Encrypt or Decrypt)
<TARGET_DIR>  Enter the Target Dir here (This is the place where your Encrypted or Decrypted files will go)

Options:
-k, --key-file <KEY_FILE>    Enter the Filename containing your Key here. This is used to either Encrypt or Decrypt the Source Dir files
-o, --operation <OPERATION>  Enter the Operation you want to perform on the Source Dir using the Key you provided [possible values: encrypt, decrypt]
-t, --threads <THREADS>      Optionally you can choose to provide number of threads [default: 8]
-h, --help                   Print help
-V, --version                Print version
```
for example, say if you want to encrypt all the files in directory say `./source-dir` using a 32 bytes key (example key: **Thisi/MyKeyT0Encryp%thislastTime**) which is maintained in a keyfile, and create a target directory say `./target-dir` which will hold the encrypted files
by **retaining the complete folder structure of the source-dir and its sub-directories in the target-dir**, then you can run the command like this
```
cargo run ../source-dir ../target-dir --key-file=../keyfile --operation=encrypt
```
or
```
./rufendec ./source-dir ./target-dir --key-file=./keyfile --operation=encrypt
```
Next, say you deleted the source-dir after encryption, and now you want the decrypted files and their respective directory structure back.
To decrypt the encrypted files inside the target-dir you currently have, just run the below command. Once finished, your original files will be back in your source-dir
```
cargo run ../target-dir ../source-dir --key-file=../keyfile --operation=decrypt
```
or
```
./rufendec ./target-dir ./source-dir --key-file=./keyfile --operation=decrypt
```
In the above examples, the names `source-dir` and `target-dir` are arbitrary. You can use any names to your source and target directories
