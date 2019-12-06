# go-sm4

`go-sm4` golang sm4 encrypt


## Installation

Use [`go get`](https://golang.org/cmd/go/#hdr-Download_and_install_packages_and_dependencies) to install and update:

```sh
$ go get -u github.com/scloudrun/go-sm4
```

## Quick start
 
```sh
# assume the following codes in example.go file
$ cat example.go
```

```go
package main

import "github.com/scloudrun/go-sm4"

var (
	defaultKey     = []byte("0000000000000000")
	defaultIv      = []byte("1111111111111111")
	defaultEncData = []byte("scloudrun")
	defaultEncByte = []byte{54, 214, 183, 79, 105, 233, 133, 146, 228, 57, 231, 154, 21, 241, 170, 7}
)

func main() {
    fmt.Println(sm4lib.Sm4Enc(defaultKey,defaultIv,defaultEncData,true))
}
```

```
# run example.go
$ go run example.go
```

## Todo
- extend
