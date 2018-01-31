# Vanitygen Cash ![](https://img.shields.io/badge/build-passing-brightgreen.svg) [![](https://img.shields.io/badge/download-click%20me!-blue.svg)](https://github.com/DesWurstes/vanitygen/blob/master/releases)

Vanitygen for Bitcoin Cash!

```
$ '/Users/Mevanitygen/oclvanitygen' -d 2 qrelay2
Difficulty: 130150524
Pattern: qrelay2
Address: bitcoincash:qrelay2wpzd34hgurjrf8hfke9xcg0mthgx4sgfwuy
Privkey: 5KUNEbYAEL6W1TowXuXkItWontWorkRSaCBm2JhJFN5tFhHZNAJvvK
```

## Download

The compiled binaries can be found at [releases](https://github.com/DesWurstes/vanitygen/blob/master/releases)

## Tips

Alphabet: `023456789acdefghjklmnpqrstuvwxyz`

- The first character should be `q`

- The second character should be either `q`, `p`, `z`, or `z`, however you can type any other character, it will put a `q` behind it (e.g. `qh0dl` => `qqh0l`)

## To build:

Mac & Linux

    make

Windows

    make -f Makefile.Win32

### Significant changes made (to comply with AGPL v3)

- Make it generate addresses in CashAddr format

- Fix some warnings

### TODOs:

- Remove "version byte"

- Fix prefixes that contain only `q`s (can be used safely, just tries to find an address with
more `q`s)

- Base58 required the expected prefix number to be converted to a BigNum. Base32 doesn't require this.
