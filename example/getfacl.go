package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/naegelejd/go-acl"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
	}

	for i := 0; i < flag.NArg(); i++ {
		fname := flag.Arg(i)
		acl, err := acls.GetFile(fname, acls.TYPE_ACCESS)
		if err != nil {
			log.Fatalf("Failed to get ACL from %s (%s)", fname, err)
		}

		str, err := acl.ToText()
		if err != nil {
			log.Fatalf("Failed to get string representation of ACL (%s)", err)
		}

		fmt.Printf("# file: %s\n# user: %s\n# group: %s\n", fname, usr, grp)
	}

}
