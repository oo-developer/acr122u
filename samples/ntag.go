package samples

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/oo-developer/acr122u/hardware"
	"github.com/oo-developer/acr122u/ntag"
)

func NtagSample(reader *hardware.Reader) {
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
