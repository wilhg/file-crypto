# File Crypto
[![Build Status](https://travis-ci.com/cuebyte/file-crypto.svg?branch=master)](https://travis-ci.com/cuebyte/file-crypto)
[![Build status](https://ci.appveyor.com/api/projects/status/o749accf9x6bewf3?svg=true)](https://ci.appveyor.com/project/cuebyte/file-crypto)

A high performace cross-platform command line tool for fastly encrypting / decrypting any file with AES-256-GCM, verifying the integrity and the security with HMAC-SHA512.

## Getting Started
### Installing
```bash
cargo install file-crypto
```

### Usage
The encrypt/decrypt mode flag can be ignore, the application will detect the mode by the suffix of the file. Encrypted file will be end with `.fc` suffix.

By the way, you can always use the flag `-e` or `-d` to set the encrypt / decrypt mode.
#### Encrypt file
```bash
file-crypto -e /your/any/file/path
```

#### Encrypt file with custom key
```bash
file-crypto -e -k yourkey /your/any/file/path
```

#### Decrypt file
```bash
file-crypto -d -k yourkey /your/any/file/path
```

## Built With

* [Rayon](https://crates.io/crates/rayon/) - The parallelism library for parallelly reading/writing file
* [Ring](https://crates.io/crates/ring/) - Using the AES-256-GCM and HMAC-SHA512
* [Memmap](https://crates.io/crates/memmap/) - For memory-mapped file IO
* [Clap](https://crates.io/crates/clap/) - For parsing command line arguments

## License

`file-crypto` is primarily distributed under the terms of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2018 Wei Huang.