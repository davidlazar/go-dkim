package main

import (
	"fmt"
	"github.com/davidlazar/go-dkim/dkim"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	log.SetFlags(log.Lshortfile)
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <email_file>...\n", os.Args[0])
		return
	}

	for _, path := range os.Args[1:] {
		fmt.Printf("%s: ", path)

		msg, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Printf("ioutil.ReadFile: %v\n", err)
			continue
		}

		ok, err := dkim.VerifyMessage(msg)
		if err != nil {
			fmt.Printf("dkim.VerifyMessage: %v\n", err)
			continue
		}

		if ok {
			fmt.Println("success")
		} else {
			fmt.Println("not good")
		}
	}
}
