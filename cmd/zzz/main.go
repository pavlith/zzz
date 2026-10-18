package main

import (
 "log"
 "github.com/pavlith/zzz/back/cli"
)

func main() {
 if err := cli.Execute(); err != nil { log.Fatal(err) }
}
