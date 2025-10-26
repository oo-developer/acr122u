package classic

import (
	"fmt"

	"github.com/ebfe/scard"
	"github.com/oo-developer/acr122u/hardware"
)

const (
	KeyTypeA = 0x60
	KeyTypeB = 0x61
)

var DefaultKeys = map[string]struct {
	KeyA  []byte
	KeyB  []byte
	Usage string
}{
	"factory": {
		KeyA:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		KeyB:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		Usage: "Factory Default",
	},
	"access_hid": {
		KeyA:  []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
		KeyB:  []byte{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5},
		Usage: "HID Access Control",
	},
	"zero": {
		KeyA:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		KeyB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		Usage: "Hotel/Student Cards",
	},
	"chinese": {
		KeyA:  []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
		KeyB:  []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
		Usage: "Chinese Door Locks",
	},
	"mifare_std": {
		KeyA:  []byte{0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A},
		KeyB:  []byte{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
		Usage: "MIFARE Standard",
	},
	"nfc": {
		KeyA:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		KeyB:  []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		Usage: "NFC Forum",
	},
	"sony": {
		KeyA:  []byte{0x12, 0x34, 0xAB, 0xCD, 0xEF, 0x12},
		KeyB:  []byte{0x34, 0xAB, 0xCD, 0xEF, 0x12, 0x34},
		Usage: "Sony/FeliCa",
	},
}

type Classic struct {
	ctx    *scard.Context
	card   *scard.Card
	reader string
}

// NewClassic initializes a new hardware
func NewClassic(reader *hardware.Reader) *Classic {
	return &Classic{
		ctx:    reader.Ctx(),
		card:   reader.Card(),
		reader: reader.Reader(),
	}
}

func (m *Classic) getVersion() []byte {
	// GET_VERSION command for NTAG/Ultralight EV1
	cmd := []byte{0xFF, 0x00, 0x00, 0x00, 0x02, 0x60, 0x00}
	rsp, err := m.card.Transmit(cmd)
	if err != nil {
		return nil
	}

	if len(rsp) < 2 {
		return nil
	}

	// Check for successful response
	if rsp[len(rsp)-2] == 0x90 && rsp[len(rsp)-1] == 0x00 {
		return rsp[:len(rsp)-2]
	}

	return nil
}

func (m *Classic) LoadKey(keyNumber byte, key []byte) error {
	if len(key) != 6 {
		return fmt.Errorf("key must be 6 bytes")
	}

	cmd := []byte{0xFF, 0x82, 0x00, keyNumber, 0x06}
	cmd = append(cmd, key...)

	rsp, err := m.card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("failed to load key: %v", err)
	}

	if len(rsp) != 2 || rsp[0] != 0x90 || rsp[1] != 0x00 {
		return fmt.Errorf("key load failed: %v", rsp)
	}

	return nil
}

func (m *Classic) Authenticate(block byte, keyType byte, keyNumber byte) error {
	cmd := []byte{0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, keyType, keyNumber}

	rsp, err := m.card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	if len(rsp) != 2 || rsp[0] != 0x90 || rsp[1] != 0x00 {
		return fmt.Errorf("authentication error: %v", rsp)
	}

	return nil
}

// ReadBlock reads a 16-byte block from the card
func (m *Classic) ReadBlock(block byte) ([]byte, error) {
	cmd := []byte{0xFF, 0xB0, 0x00, block, 0x10}

	rsp, err := m.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	if len(rsp) < 2 {
		return nil, fmt.Errorf("invalid response length")
	}

	if rsp[len(rsp)-2] != 0x90 || rsp[len(rsp)-1] != 0x00 {
		return nil, fmt.Errorf("read error: %02X %02X", rsp[len(rsp)-2], rsp[len(rsp)-1])
	}

	return rsp[:len(rsp)-2], nil
}

// WriteBlock writes a 16-byte block to the card
func (m *Classic) WriteBlock(block byte, data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("data must be 16 bytes")
	}

	cmd := []byte{0xFF, 0xD6, 0x00, block, 0x10}
	cmd = append(cmd, data...)

	rsp, err := m.card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	if len(rsp) != 2 || rsp[0] != 0x90 || rsp[1] != 0x00 {
		return fmt.Errorf("write error: %v", rsp)
	}

	return nil
}

// ChangeKeys changes the keys for a sector
// sector: the sector number (0-15 for MIFARE Classic 1K)
// newKeyA: new Key A (6 bytes), or nil to keep existing
// newKeyB: new Key B (6 bytes), or nil to keep existing
// accessBits: 4 bytes of access conditions (or nil for default)
// currentKeyType: KeyTypeA or KeyTypeB - which key to use for authentication
// currentKey: the current key to authenticate with
func (m *Classic) ChangeKeys(sector byte, newKeyA []byte, newKeyB []byte, accessBits []byte, currentKeyType byte, currentKey []byte) error {
	if newKeyA != nil && len(newKeyA) != 6 {
		return fmt.Errorf("Key A must be 6 bytes")
	}
	if newKeyB != nil && len(newKeyB) != 6 {
		return fmt.Errorf("Key B must be 6 bytes")
	}
	if accessBits != nil && len(accessBits) != 4 {
		return fmt.Errorf("access bits must be 4 bytes")
	}

	// Calculate the sector trailer block number
	// For MIFARE Classic 1K: block = sector * 4 + 3
	trailerBlock := sector*4 + 3

	// Load the current key
	if err := m.LoadKey(0x00, currentKey); err != nil {
		return fmt.Errorf("failed to load current key: %v", err)
	}

	// Authenticate with current key
	if err := m.Authenticate(trailerBlock, currentKeyType, 0x00); err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	// Read current sector trailer to preserve values we're not changing
	currentTrailer, err := m.ReadBlock(trailerBlock)
	if err != nil {
		return fmt.Errorf("failed to read sector trailer: %v", err)
	}

	// Build new sector trailer
	newTrailer := make([]byte, 16)

	// Key A (bytes 0-5)
	if newKeyA != nil {
		copy(newTrailer[0:6], newKeyA)
	} else {
		copy(newTrailer[0:6], currentTrailer[0:6])
	}

	// Access bits (bytes 6-9)
	if accessBits != nil {
		copy(newTrailer[6:10], accessBits)
	} else {
		// Default access conditions (transport configuration)
		// FF 07 80 69 - allows both keys to read/write all blocks
		newTrailer[6] = 0xFF
		newTrailer[7] = 0x07
		newTrailer[8] = 0x80
		newTrailer[9] = 0x69
	}

	// Key B (bytes 10-15)
	if newKeyB != nil {
		copy(newTrailer[10:16], newKeyB)
	} else {
		copy(newTrailer[10:16], currentTrailer[10:16])
	}

	// Write the new sector trailer
	if err := m.WriteBlock(trailerBlock, newTrailer); err != nil {
		return fmt.Errorf("failed to write new keys: %v", err)
	}

	return nil
}

// GetSectorTrailerBlock returns the block number of a sector's trailer
func GetSectorTrailerBlock(sector byte) byte {
	return sector*4 + 3
}

func (m *Classic) TryStandardKeys(blockNum byte, keyType int) string {
	for name, keys := range DefaultKeys {
		fmt.Sprintf("     Probing %s\n", name)
		key := keys.KeyA
		if KeyTypeB == keyType {
			key = keys.KeyB
		}
		err := m.LoadKey(0x00, key)
		if err != nil {
			return ""
		}
		err = m.Authenticate(blockNum, KeyTypeA, 0x00)
		if err == nil {
			return name
		}

	}
	return ""
}
