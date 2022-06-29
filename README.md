# Crypto Go

CryptoGo is an improved version of Gokart, which adds more cryptographic rules. CryptoGo is an effective static analyzer.

## Install

You can install CryptoGo locally by using any one of the options listed below.

### Install with `go install`

```shell
$ go install github.com/1047261438/cryptogo
```

Extract the downloaded archive

```shell
$ tar -xvf cryptogo_${VERSION}_${ARCH}.tar.gz
```

Move the `cryptogo` binary into your path:

```shell
$ mv ./cryptogo /usr/local/bin/
```

### Clone and build yourself

```shell
# clone the CryptoGo repo
$ git clone https://github.com/1047261438/cryptogo.git

# navigate into the repo directory and build
$ cd cryptogo
$ go build

# Move the cryptogo binary into your path
$ mv ./cryptogo /usr/local/bin
```

## Usage

### Run CryptoGo on a Go module in the current directory

```shell
# running without a directory specified defaults to '.'
cryptogo scan <flags>
```

### Scan a Go module in a different directory

```shell
cryptogo scan <directory> <flags> 
```

### Get Help

```shell
cryptogo help
```
