# des-rs
DES implementation in Rust

# Example

```
extern crate des_rs_krautcat;

let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
let message = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
let cipher = des_rs_krautcat::encrypt(&message, &key);
let message = des_rs_krautcat::decrypt(&cipher, &key);
```

# Usage

Des exports two functions: `encrypt` and `decrypt`.
Use the former to encrypt some data with a key and the later to decrypt the data.
