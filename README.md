# Vanitygen Cash ![](https://img.shields.io/badge/build-passing-brightgreen.svg) [![](https://img.shields.io/badge/download-click%20me!-blue.svg)](https://github.com/cashaddress/vanitygen-cash/releases) ![](https://img.shields.io/github/downloads/cashaddress/vanitygen-cash/total.svg)

Vanitygen for Bitcoin Cash! Crafted by the creators of [CashAddress.Github.io](https://cashaddress.github.io/)

![Vanitygen Cash on Hyper](https://user-images.githubusercontent.com/23437045/36631365-a126c57e-1987-11e8-9121-5a3da032d85d.png)

## Download

The compiled binaries for Windows, Mac and Linux can be found at [releases](https://github.com/cashaddress/vanitygen-cash/releases).

## Tips

Alphabet: `023456789acdefghjklmnpqrstuvwxyz`

- The first character must be `q`

- The second character must be either `p`, `q`, `r`, or `z`.

## To build:

Mac

    brew install openssl@1.1 hyperscan
    make

Linux

    sudo apt-get install libhyperscan-dev g++-7 ocl-icd-opencl-dev
    make

Windows

[too long](/INSTALL)

### Significant changes made (to comply with AGPL v3)

- **Make it generate addresses in CashAddr format (remove case sensitivity...)**

- **Let Vanitygen search for both compressed and uncompressed addresses**

- **Output in TSV and CSV formats**

- **Replace PCRE with Hyperscan for efficient regex search!**

- Fix some warnings

- Make it OpenSS 1.1L compatible

### TODOs:

- Allow to choose between compressed and uncompressed addresses

- Allow to choose between "gethash" and "prefix"

- Port libsecp256k1 code (long term)
