package main

import (
    "github.com/naegelejd/go-acl/acls"
    "log"
    "fmt"
    "os"
)

func main() {
    filename := os.Args[1]

    acl, err := acls.GetFile(filename, acls.TYPE_ACCESS)
    if err != nil {
        log.Print("Failed to get ACL from ", filename)
        log.Fatal(err)
    }

    str, err := acl.ToText()
    if err != nil {
        log.Print("Failed to get string representation of ACL")
        log.Fatal(err)
    }

    fmt.Print("ACL repr:\n", str)

    err = acls.Free(acl)
    if err != nil {
        log.Print("Failed to free ACL")
        log.Fatal(err)
    }
}
