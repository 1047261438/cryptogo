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
$ tar -xvf gokart_${VERSION}_${ARCH}.tar.gz
```

Move the `gokart` binary into your path:

```shell
$ mv ./gokart /usr/local/bin/
```

### Clone and build yourself

```shell
# clone the CryptoGo repo
$ git clone https://github.com/1047261438/cryptogo.git

# navigate into the repo directory and build
$ cd gokart
$ go build

# Move the gokart binary into your path
$ mv ./gokart /usr/local/bin
```

## Usage

### Run CryptoGo on a Go module in the current directory

```shell
# running without a directory specified defaults to '.'
gokart scan <flags>
```

### Scan a Go module in a different directory

```shell
gokart scan <directory> <flags> 
```

### Get Help

```shell
gokart help
```
