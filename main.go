package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func main() {
	reader, err := NewReader()
	if err != nil {
		fmt.Printf("[ERROR] Failed to create reader: %v\n", err)
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
		log.Printf("[ERROR] Failed to connect: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Connected!")

	// Get UID
	uid, err := reader.GetUID()
	if err != nil {
		log.Printf("[ERROR] Failed to get UID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Card UID: %s\n", hex.EncodeToString(uid))

	cardType, err := reader.DetectCardType()
	if err != nil {
		log.Printf("[ERROR] Failed to get card type: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Card type: %s\n", cardType.Type)

	// Default MIFARE Classic key (all 0xFF)
	defaultKey := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	fmt.Println("[OK] Loading authentication key...")
	if err := reader.LoadKey(0x00, defaultKey); err != nil {
		log.Printf("[ERROR] Failed to load key: %v\n", err)
	}

	// Example: Read block 4
	blockNum := byte(4)
	fmt.Printf("[OK] Authenticating block %d...\n", blockNum)
	if err := reader.Authenticate(blockNum, KeyTypeA, 0x00); err != nil {
		fmt.Printf("[ERROR] Authentication failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[OK] Reading block %d...\n", blockNum)
	data, err := reader.ReadBlock(blockNum)
	if err != nil {
		fmt.Printf("[ERROR] Read failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Block %d data: %s\n", blockNum, hex.EncodeToString(data))
	fmt.Printf("[OK] Block %d ASCII: %q\n", blockNum, data)

	// Example: Write to block 4
	// WARNING: Be careful not to write to sector trailer blocks (every 4th block)
	// as this contains access keys and conditions
	newData := []byte("1c00901100b0020A") // Must be exactly 16 bytes
	if len(newData) != 16 {
		fmt.Println("Data must be 16 bytes")
		os.Exit(1)
	}

	fmt.Printf("[OK] Writing to block %d...\n", blockNum)
	if err := reader.WriteBlock(blockNum, newData); err != nil {
		fmt.Printf("[ERROR] Write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Write successful!")

	// Read back to verify
	fmt.Printf("[OK] Reading block %d again to verify...\n", blockNum)
	verifyData, err := reader.ReadBlock(blockNum)
	if err != nil {
		fmt.Printf("[ERROR] Verify read failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Verified data: %s\n", hex.EncodeToString(verifyData))
	fmt.Printf("[OK] Verified ASCII: %q\n", verifyData)
}
