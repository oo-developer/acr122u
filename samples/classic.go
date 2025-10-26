package samples

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/oo-developer/acr122u/classic"
	"github.com/oo-developer/acr122u/hardware"
)

func ClassicSample(reader *hardware.Reader) {
	classicReader := classic.NewClassic(reader)

	blockNum := byte(4)
	key := classicReader.TryStandardKeys(blockNum, classic.KeyTypeA)
	fmt.Printf("[OK] Default key found: %s\n", key)
	fmt.Printf("[OK] Key: %s\n", hex.EncodeToString(classic.DefaultKeys[key].KeyA))

	// Default MIFARE Classic key (all 0xFF)
	defaultKey := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	//defaultKey := []byte{0x12, 0x34, 0xAB, 0xCD, 0xEF, 0x12}

	fmt.Println("[OK] Loading authentication key...")
	if err := classicReader.LoadKey(0x00, defaultKey); err != nil {
		log.Printf("[ERROR] Failed to load key: %v\n", err)
		os.Exit(1)
	}

	//blockNum := byte(4)
	fmt.Printf("[OK] Authenticating block %d...\n", blockNum)
	if err := classicReader.Authenticate(blockNum, classic.KeyTypeA, 0x00); err != nil {
		fmt.Printf("[ERROR] Authentication failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[OK] Reading block %d...\n", blockNum)
	data, err := classicReader.ReadBlock(blockNum)
	if err != nil {
		fmt.Printf("[ERROR] Read failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Block %d data: %s\n", blockNum, hex.EncodeToString(data))
	fmt.Printf("[OK] Block %d ASCII: %q\n", blockNum, data)

	newData := []byte("1c00901100b0020A") // Must be exactly 16 bytes
	if len(newData) != 16 {
		fmt.Println("Data must be 16 bytes")
		os.Exit(1)
	}

	fmt.Printf("[OK] Writing to block %d...\n", blockNum)
	if err := classicReader.WriteBlock(blockNum, newData); err != nil {
		fmt.Printf("[ERROR] Write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Write successful!")

	fmt.Printf("[OK] Reading block %d again to verify...\n", blockNum)
	verifyData, err := classicReader.ReadBlock(blockNum)
	if err != nil {
		fmt.Printf("[ERROR] Verify read failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[OK] Verified data: %s\n", hex.EncodeToString(verifyData))
	fmt.Printf("[OK] Verified ASCII: %q\n", verifyData)

	fmt.Println("[OK] Dumping card ... (64 blocks)")
	for ii := 0; ii < 64; ii++ {
		classicReader.Authenticate(byte(ii), classic.KeyTypeA, 0x00)
		data, err := classicReader.ReadBlock(byte(ii))
		if err == nil {
			fmt.Printf("    [%02d] %s\n", ii, hex.EncodeToString(data))
		}
	}
}
