package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/oo-developer/acr122u/hardware"
)

func main() {
	reader, err := hardware.NewReader()
	if err != nil {
		fmt.Printf("[ERROR] Failed to create hardware: %v\n", err)
		os.Exit(1)
	}
	defer reader.Close()

	// List available readers
	readers, err := reader.ListReaders()
	if err != nil {
		log.Printf("[ERROR] Failed to list readers: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[OK] Available readers:")
	if len(readers) == 0 {
		fmt.Println("[ERROR] No readers detected")
		os.Exit(1)
	}
	for i, r := range readers {
		fmt.Printf("     %d: %s\n", i, r)
	}
	reader.UseReader(readers[0])

	for {
		fmt.Println("[OK] Waiting for card ...")
		err = reader.WaitForCard()
		if err != nil {
			fmt.Printf("[ERROR] Failed to wait for card: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[OK] Card ready")

		// Connect to card
		fmt.Println("[OK] Connecting to card...")
		if err := reader.Connect(); err != nil {
			reader.Disconnect()
		}
		fmt.Println("[OK] Connected!")
		fmt.Printf("[OK] Card UID : %s\n", hex.EncodeToString(reader.CardInfo().UID))
		fmt.Printf("[OK] Card type: %s\n", reader.CardInfo().Type)

		reader.Disconnect()
	}
	//samples.NtagSample(reader)
	//samples.ClassicSample(reader)
}
