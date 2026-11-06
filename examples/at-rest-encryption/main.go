package main

import (
	"fmt"
	"log"
	"os"

	"github.com/disaster37/raft/storage"
)

func main() {
	keyFile := "/tmp/raft-at-rest-keys.json"
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		if err := storage.GenerateKeyFile(keyFile); err != nil {
			log.Fatal(err)
		}
	}
	keeper, err := storage.LoadAESGCMKeeper(keyFile, "raft.at-rest.v1")
	if err != nil {
		log.Fatal(err)
	}
	sealed, err := keeper.SealString("sensitive-value")
	if err != nil {
		log.Fatal(err)
	}
	opened, err := keeper.OpenString(sealed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("sealed=%s\nopened=%s\n", sealed, opened)
}
