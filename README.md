# Vanitygen Cash ![](https://img.shields.io/badge/build-passing-brightgreen.svg) [![](https://img.shields.io/badge/download-click%20me!-blue.svg)](https://github.com/cashaddress/vanitygen-cash/releases) ![](https://img.shields.io/github/downloads/cashaddress/vanitygen-cash/total.svg)

Vanitygen for Bitcoin Cash! Crafted by the creators of [CashAddress.Github.io](https://cashaddress.github.io/)

```
$ '/Users/Mevanitygen/oclvanitygen' -d 2 qrelay2
Difficulty: 130150524
Pattern: qrelay2
Address: bitcoincash:qrelay2wpzd34hgurjrf8hfke9xcg0mthgx4sgfwuy
Privkey: 5KUNEbYAEL6W1TowXuXkIEasTEreGGWorkRSaCBm2JhJFN5tFhHZNAJvvK
```

## Download

The compiled binaries can be found at [releases](https://github.com/cashaddress/vanitygen-cash/releases)

## Tips

Alphabet: `023456789acdefghjklmnpqrstuvwxyz`

- The first character should be `q`

- The second character should be either `q`, `p`, `z`, or `r`, however, you can type any other character, it will put a `q` behind it (e.g. `qh0dl` => `qqh0dl`)

## To build:

Mac (compiles the latest gcc, 50+ minutes)

    brew install gcc openssl pcre
    make

Linux

    sudo apt-get install libpcre3-dev g++-7 ocl-icd-opencl-dev
    make

Windows

[too long](/INSTALL)

### Significant changes made (to comply with AGPL v3)

- Make it generate addresses in CashAddr format

- Fix some warnings

### TODOs:

- Remove "version byte" completely

- Base58 required the expected prefix number to be converted to a BigNum. Base32 doesn't require this. ([These lines](https://github.com/samr7/vanitygen/blob/master/pattern.c#L1478-L1481))

- Port libsecp256k1 code (long term)
