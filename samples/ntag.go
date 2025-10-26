package samples

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/oo-developer/acr122u/hardware"
	"github.com/oo-developer/acr122u/ntag"
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

	fmt.Println("[OK] Waiting for card ...")
	err = reader.WaitForCard()
	if err != nil {
		fmt.Printf("[ERROR] Failed to wait for card: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Card ready")

	// Connect to card
	fmt.Println("[OK] Connecting to card ...")
	if err := reader.Connect(); err != nil {
		log.Printf("[ERROR] Failed to connect: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[OK] Connected!")
	fmt.Printf("[OK] Card UID : %s\n", hex.EncodeToString(reader.CardInfo().UID))
	fmt.Printf("[OK] Card type: %s\n", reader.CardInfo().Type)

	ntagReader := ntag.NewNTAG(reader)

	page0, err := ntagReader.ReadPages(0)
	fmt.Printf("[OK] Pages 0: %s\n", hex.EncodeToString(page0))
	page0s, err := ntagReader.ReadPage(0)
	page1s, err := ntagReader.ReadPage(1)
	page2s, err := ntagReader.ReadPage(2)
	page3s, err := ntagReader.ReadPage(3)
	fmt.Printf("[OK] Page 0: %s\n", hex.EncodeToString(page0s))
	fmt.Printf("[OK] Page 1: %s\n", hex.EncodeToString(page1s))
	fmt.Printf("[OK] Page 2: %s\n", hex.EncodeToString(page2s))
	fmt.Printf("[OK] Page 3: %s\n", hex.EncodeToString(page3s))

	ntagType, err := ntagReader.DetectChipType()
	if err != nil {
		log.Printf("[ERROR] Failed to detect chip type: %v\n", err)
		return
	}
	fmt.Printf("[OK] Chip type: %s\n", ntagType.Name)
}
