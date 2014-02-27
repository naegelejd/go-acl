package main

import (
    "github.com/naegelejd/go-acl/acls"
    "log"
    "os"
)

func main() {
    filename := os.Args[1]

    acl, err := acls.GetFile(filename, acls.TYPE_ACCESS)
    if err != nil {
        log.Fatal("Failed to get ACL from ", filename)
    }

    size := acl.Size()
    str, err := acl.ToText()
    if err != nil {
        log.Fatal("Failed to get string representation of ACL")
    }

    log.Print("ACL repr: ", str)
    log.Print("ACL size: ", size)

    err = acls.Free(acl)
    if err != nil {
        log.Fatal("Failed to free ACL")
    }
}
