package main

import (
	"fmt"
	"time"

	"github.com/ebfe/scard"
)

type CardType int

const (
	CardTypeUnknown CardType = iota
	CardTypeMifareClassic1K
	CardTypeMifareClassic4K
	CardTypeMifareUltralight
	CardTypeMifareUltralightC
	CardTypeMifareUltralightEV1
	CardTypeMifarePlus
	CardTypeMifareDESFire
	CardTypeNTAG213
	CardTypeNTAG215
	CardTypeNTAG216
	CardTypeISO14443A
	CardTypeISO14443B
)

// String returns the human-readable name of the card type
func (ct CardType) String() string {
	switch ct {
	case CardTypeMifareClassic1K:
		return "MIFARE Classic 1K"
	case CardTypeMifareClassic4K:
		return "MIFARE Classic 4K"
	case CardTypeMifareUltralight:
		return "MIFARE Ultralight"
	case CardTypeMifareUltralightC:
		return "MIFARE Ultralight C"
	case CardTypeMifareUltralightEV1:
		return "MIFARE Ultralight EV1"
	case CardTypeMifarePlus:
		return "MIFARE Plus"
	case CardTypeMifareDESFire:
		return "MIFARE DESFire"
	case CardTypeNTAG213:
		return "NTAG213"
	case CardTypeNTAG215:
		return "NTAG215"
	case CardTypeNTAG216:
		return "NTAG216"
	case CardTypeISO14443A:
		return "ISO14443A (Generic)"
	case CardTypeISO14443B:
		return "ISO14443B"
	default:
		return "Unknown"
	}
}

// CardInfo contains detailed information about a detected card
type CardInfo struct {
	Type        CardType
	UID         []byte
	ATR         []byte // Answer to Reset
	SAK         byte   // Select Acknowledge
	ATQA        []byte // Answer to Request Type A
	Capacity    int    // Storage capacity in bytes
	BlockCount  int    // Number of blocks
	SectorCount int    // Number of sectors
	Protocol    string // Communication protocol
}

const (
	// MIFARE Classic authentication keys
	KeyTypeA = 0x60
	KeyTypeB = 0x61
)

type Reader struct {
	ctx    *scard.Context
	card   *scard.Card
	reader string
}

// NewReader initializes a new reader
func NewReader() (*Reader, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to establish context: %v", err)
	}

	return &Reader{
		ctx: ctx,
	}, nil
}

// Close releases the reader resources
func (m *Reader) Close() error {
	if m.card != nil {
		m.card.Disconnect(scard.LeaveCard)
	}
	if m.ctx != nil {
		return m.ctx.Release()
	}
	return nil
}

func (m *Reader) WaitForCard() error {
	states := []scard.ReaderState{
		{Reader: m.reader, CurrentState: scard.StateUnaware},
	}
	for {
		err := m.ctx.GetStatusChange(states, 30*time.Second)
		if err != nil {
			return err
		}
		if states[0].EventState&scard.StatePresent != 0 {
			break
		}
	}
	return nil
}

// ListReaders returns available PC/SC readers
func (m *Reader) ListReaders() ([]string, error) {
	readers, err := m.ctx.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("failed to list readers: %v", err)
	}
	return readers, nil
}

func (m *Reader) UseReader(reader string) {
	m.reader = reader
}

// Connect connects to the first available reader with a card
func (m *Reader) Connect() error {
	if m.reader == "" {
		return fmt.Errorf("no reader selected, use: UseReader(reader string)")
	}
	card, err := m.ctx.Connect(m.reader, scard.ShareShared, scard.ProtocolT0|scard.ProtocolT1)
	if err != nil {
		return fmt.Errorf("failed to connect to reader: %v", err)
	}

	m.card = card
	return nil
}

// GetUID retrieves the card UID
func (m *Reader) GetUID() ([]byte, error) {
	if m.card == nil {
		return nil, fmt.Errorf("not connected to card")
	}

	// Send Get Data command for UID
	cmd := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}
	rsp, err := m.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get UID: %v", err)
	}

	if len(rsp) < 2 {
		return nil, fmt.Errorf("invalid response length")
	}

	// Check status bytes (should be 0x90 0x00 for success)
	if rsp[len(rsp)-2] != 0x90 || rsp[len(rsp)-1] != 0x00 {
		return nil, fmt.Errorf("error status: %02X %02X", rsp[len(rsp)-2], rsp[len(rsp)-1])
	}

	return rsp[:len(rsp)-2], nil
}

// DetectCardType detects the type of card present
func (m *Reader) DetectCardType() (*CardInfo, error) {
	if m.card == nil {
		return nil, fmt.Errorf("not connected to card")
	}

	info := &CardInfo{}

	// Get UID
	uid, err := m.GetUID()
	if err != nil {
		return nil, fmt.Errorf("failed to get UID: %v", err)
	}
	info.UID = uid

	// Get ATR (Answer to Reset) from card status
	status, err := m.card.Status()
	if err == nil {
		info.ATR = status.Atr

		// Determine protocol
		switch status.ActiveProtocol {
		case scard.ProtocolT0:
			info.Protocol = "T=0"
		case scard.ProtocolT1:
			info.Protocol = "T=1"
		default:
			info.Protocol = "Unknown"
		}
	}

	// Parse ATR to determine card type
	// ATR format varies, but we can extract key information
	if len(info.ATR) > 0 {
		info.Type = m.parseCardTypeFromATR(info.ATR, uid)
	}

	// Set capacity and block/sector info based on card type
	switch info.Type {
	case CardTypeMifareClassic1K:
		info.Capacity = 1024
		info.BlockCount = 64
		info.SectorCount = 16
	case CardTypeMifareClassic4K:
		info.Capacity = 4096
		info.BlockCount = 256
		info.SectorCount = 40
	case CardTypeMifareUltralight:
		info.Capacity = 64
		info.BlockCount = 16
		info.SectorCount = 0
	case CardTypeMifareUltralightC:
		info.Capacity = 192
		info.BlockCount = 48
		info.SectorCount = 0
	case CardTypeMifareUltralightEV1:
		info.Capacity = 888 // EV1 varies, this is 80h variant
		info.BlockCount = 41
		info.SectorCount = 0
	case CardTypeNTAG213:
		info.Capacity = 180
		info.BlockCount = 45
		info.SectorCount = 0
	case CardTypeNTAG215:
		info.Capacity = 540
		info.BlockCount = 135
		info.SectorCount = 0
	case CardTypeNTAG216:
		info.Capacity = 924
		info.BlockCount = 231
		info.SectorCount = 0
	}

	return info, nil
}

// parseCardTypeFromATR analyzes the ATR to determine card type
func (m *Reader) parseCardTypeFromATR(atr []byte, uid []byte) CardType {
	// ATR historical bytes often contain card type information
	// Format: 3B 8X 80 01 XX XX XX XX XX XX XX XX XX XX

	if len(atr) < 4 {
		return CardTypeUnknown
	}

	// Check for common MIFARE patterns in ATR
	// MIFARE Classic typically has specific historical bytes

	// Try to determine by UID length and SAK
	//uidLen := len(uid)

	// Get SAK (Select Acknowledge) - try reading it
	sak, atqa := m.getCardAttributes()

	// MIFARE Classic 1K: SAK = 0x08
	if sak == 0x08 {
		return CardTypeMifareClassic1K
	}

	// MIFARE Classic 4K: SAK = 0x18
	if sak == 0x18 {
		return CardTypeMifareClassic4K
	}

	// MIFARE Ultralight: SAK = 0x00, ATQA = 0x0044
	if sak == 0x00 {
		if len(atqa) >= 2 && atqa[0] == 0x44 && atqa[1] == 0x00 {
			// Further distinguish between UL variants
			// Try to read version info (for EV1/NTAG)
			version := m.getVersion()
			if version != nil {
				return m.parseUltralightVariant(version)
			}
			return CardTypeMifareUltralight
		}
	}

	// MIFARE DESFire: SAK = 0x20
	if sak == 0x20 {
		return CardTypeMifareDESFire
	}

	// MIFARE Plus: SAK = 0x10, 0x11, or 0x20 with specific ATQA
	if sak == 0x10 || sak == 0x11 {
		return CardTypeMifarePlus
	}

	// Check ATR historical bytes for specific patterns
	for i := 0; i < len(atr)-1; i++ {
		// Look for MIFARE Classic signature in ATR
		if i+2 < len(atr) {
			// Common pattern for MIFARE Classic 1K
			if atr[i] == 0x80 && atr[i+1] == 0x01 {
				// Next bytes might indicate card type
				if i+3 < len(atr) {
					cardCode := atr[i+2]
					switch cardCode {
					case 0x80:
						return CardTypeMifareClassic1K
					case 0x38:
						return CardTypeMifareClassic4K
					}
				}
			}
		}
	}

	// Generic ISO14443A if we can't determine specific type
	return CardTypeISO14443A
}

// getCardAttributes retrieves SAK and ATQA using direct commands
func (m *Reader) getCardAttributes() (sak byte, atqa []byte) {
	// This is a simplified version - actual implementation may vary by reader
	// Some readers expose this in ATR, others need special commands

	// Try to extract from ATR historical bytes if available
	status, err := m.card.Status()
	if err != nil {
		return 0, nil
	}

	atr := status.Atr
	if len(atr) >= 14 {
		// SAK is often in historical bytes around position 13
		sak = atr[13]
	}

	// ATQA is typically 2 bytes, sometimes in ATR
	if len(atr) >= 16 {
		atqa = atr[14:16]
	}

	return sak, atqa
}

// getVersion gets version information for Ultralight/NTAG cards
func (m *Reader) getVersion() []byte {
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

// parseUltralightVariant determines the specific Ultralight variant
func (m *Reader) parseUltralightVariant(version []byte) CardType {
	if len(version) < 8 {
		return CardTypeMifareUltralight
	}

	// Version format: Vendor ID, Type, Subtype, Major, Minor, Storage, Protocol
	// Byte 2: Product type
	// Byte 3: Product subtype
	// Byte 6: Storage size

	productType := version[2]
	storageSize := version[6]

	// NTAG cards
	if productType == 0x04 {
		switch storageSize {
		case 0x0F: // 144 bytes
			return CardTypeNTAG213
		case 0x11: // 504 bytes
			return CardTypeNTAG215
		case 0x13: // 888 bytes
			return CardTypeNTAG216
		}
	}

	// Ultralight variants
	if productType == 0x03 {
		switch storageSize {
		case 0x0B:
			return CardTypeMifareUltralightC
		case 0x0F:
			return CardTypeMifareUltralightEV1
		}
	}

	return CardTypeMifareUltralight
}

// LoadKey loads an authentication key into the reader
func (m *Reader) LoadKey(keyNumber byte, key []byte) error {
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

// Authenticate authenticates a block with the specified key
func (m *Reader) Authenticate(block byte, keyType byte, keyNumber byte) error {
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
func (m *Reader) ReadBlock(block byte) ([]byte, error) {
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
func (m *Reader) WriteBlock(block byte, data []byte) error {
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
func (m *Reader) ChangeKeys(sector byte, newKeyA []byte, newKeyB []byte, accessBits []byte, currentKeyType byte, currentKey []byte) error {
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
