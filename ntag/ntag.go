package ntag

import (
	"fmt"

	"github.com/ebfe/scard"
	"github.com/oo-developer/acr122u/hardware"
)

const (
	// NTAG chip types
	NTAG213 = "NTAG213"
	NTAG215 = "NTAG215"
	NTAG216 = "NTAG216"

	// Memory specifications
	NTAG213TotalPages = 45
	NTAG215TotalPages = 135
	NTAG216TotalPages = 231

	NTAG213UserPages = 36  // Pages 4-39
	NTAG215UserPages = 126 // Pages 4-129
	NTAG216UserPages = 222 // Pages 4-225

	// Special page numbers
	CapabilityContainerPage = 3
	DynamicLockBytesPage    = 2
	StaticLockBytesPage     = 2

	// APDU Commands
	CLA_DIRECT_TRANSMIT = 0xFF
	INS_GET_DATA        = 0x00
	INS_READ_BINARY     = 0xB0
	INS_UPDATE_BINARY   = 0xD6

	// NTAG Native Commands
	CMD_GET_VERSION = 0x60
	CMD_READ        = 0x30
	CMD_FAST_READ   = 0x3A
	CMD_WRITE       = 0xA2
	CMD_COMP_WRITE  = 0xA0
	CMD_PWD_AUTH    = 0x1B

	// Status Words
	SW1_SUCCESS = 0x90
	SW2_SUCCESS = 0x00
)

// NTAGType represents the detected NTAG chip type
type NTAGType struct {
	Name       string
	TotalPages int
	UserPages  int
	TotalBytes int
	UserBytes  int
}

var (
	// NTAG chip specifications
	NTAG213Spec = NTAGType{
		Name:       NTAG213,
		TotalPages: NTAG213TotalPages,
		UserPages:  NTAG213UserPages,
		TotalBytes: NTAG213TotalPages * 4,
		UserBytes:  NTAG213UserPages * 4,
	}

	NTAG215Spec = NTAGType{
		Name:       NTAG215,
		TotalPages: NTAG215TotalPages,
		UserPages:  NTAG215UserPages,
		TotalBytes: NTAG215TotalPages * 4,
		UserBytes:  NTAG215UserPages * 4,
	}

	NTAG216Spec = NTAGType{
		Name:       NTAG216,
		TotalPages: NTAG216TotalPages,
		UserPages:  NTAG216UserPages,
		TotalBytes: NTAG216TotalPages * 4,
		UserBytes:  NTAG216UserPages * 4,
	}
)

// DefaultPasswords contains common NTAG password configurations
var DefaultPasswords = map[string]struct {
	PWD   []byte
	PACK  []byte
	Usage string
}{
	"factory": {
		PWD:   []byte{0xFF, 0xFF, 0xFF, 0xFF},
		PACK:  []byte{0x00, 0x00},
		Usage: "Factory Default (no password)",
	},
	"amiibo": {
		PWD:   []byte{0x00, 0x00, 0x00, 0x00},
		PACK:  []byte{0x80, 0x80},
		Usage: "Nintendo Amiibo",
	},
	"zero": {
		PWD:   []byte{0x00, 0x00, 0x00, 0x00},
		PACK:  []byte{0x00, 0x00},
		Usage: "All zeros",
	},
	"custom": {
		PWD:   []byte{0x12, 0x34, 0x56, 0x78},
		PACK:  []byte{0xAA, 0xBB},
		Usage: "Common custom password",
	},
}

type NTAG struct {
	ctx      *scard.Context
	card     *scard.Card
	reader   string
	chipType *NTAGType
}

// NewNTAG initializes a new NTAG handler
func NewNTAG(reader *hardware.Reader) *NTAG {
	return &NTAG{
		ctx:    reader.Ctx(),
		card:   reader.Card(),
		reader: reader.Reader(),
	}
}

// GetVersion retrieves the version information from the NTAG chip
// Note: This may not work on all ACR122U firmware versions
func (n *NTAG) GetVersion() ([]byte, error) {
	// Try simple direct transmit like the Classic module does
	cmd := []byte{CLA_DIRECT_TRANSMIT, 0x00, 0x00, 0x00, 0x02, CMD_GET_VERSION, 0x00}
	rsp, err := n.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get version: %v", err)
	}

	if len(rsp) < 2 {
		return nil, fmt.Errorf("invalid response length: got %d bytes - GET_VERSION may not be supported", len(rsp))
	}

	// Check for successful response
	if rsp[len(rsp)-2] == SW1_SUCCESS && rsp[len(rsp)-1] == SW2_SUCCESS {
		return rsp[:len(rsp)-2], nil
	}

	return nil, fmt.Errorf("get version failed: %02X %02X", rsp[len(rsp)-2], rsp[len(rsp)-1])
}

// DetectChipTypeByMemory detects chip type by probing memory boundaries
// This is more reliable than GET_VERSION on some readers
func (n *NTAG) DetectChipTypeByMemory() (*NTAGType, error) {
	// NTAG memory layout:
	// NTAG213: 45 pages (0-44), user memory ends at page 39
	// NTAG215: 135 pages (0-134), user memory ends at page 129
	// NTAG216: 231 pages (0-230), user memory ends at page 225

	// Try reading page 130 (only exists on NTAG215/216)
	if _, err := n.ReadPage(130); err == nil {
		// Can read page 130, must be NTAG215 or NTAG216
		// Try reading page 226 (only exists on NTAG216)
		if _, err := n.ReadPage(226); err == nil {
			n.chipType = &NTAG216Spec
			return &NTAG216Spec, nil
		}
		n.chipType = &NTAG215Spec
		return &NTAG215Spec, nil
	}

	// Cannot read page 130, must be NTAG213
	n.chipType = &NTAG213Spec
	return &NTAG213Spec, nil
}

// DetectChipType detects the NTAG chip type (213/215/216)
// Tries GET_VERSION first, falls back to memory probing if that fails
func (n *NTAG) DetectChipType() (*NTAGType, error) {
	// Try GET_VERSION first
	version, err := n.GetVersion()
	if err == nil && len(version) >= 8 {
		// Version response format (8 bytes):
		// Byte 0: Fixed header (0x00)
		// Byte 1: Vendor ID (0x04 = NXP)
		// Byte 2: Product type (0x04 = NTAG)
		// Byte 3: Product subtype (0x02)
		// Byte 4: Major product version
		// Byte 5: Minor product version
		// Byte 6: Storage size
		// Byte 7: Protocol type

		// Storage size byte determines the chip type
		storageSize := version[6]

		switch storageSize {
		case 0x0F: // 180 bytes (NTAG213)
			n.chipType = &NTAG213Spec
			return &NTAG213Spec, nil
		case 0x11: // 540 bytes (NTAG215)
			n.chipType = &NTAG215Spec
			return &NTAG215Spec, nil
		case 0x13: // 924 bytes (NTAG216)
			n.chipType = &NTAG216Spec
			return &NTAG216Spec, nil
		}
	}

	// GET_VERSION failed or returned unexpected data, use memory probing
	return n.DetectChipTypeByMemory()
}

// ReadPage reads a 4-byte page from the NTAG card
func (n *NTAG) ReadPage(page byte) ([]byte, error) {
	// Standard READ BINARY APDU
	// FF B0 00 [page] [length]
	cmd := []byte{CLA_DIRECT_TRANSMIT, INS_READ_BINARY, 0x00, page, 0x04}

	rsp, err := n.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	if len(rsp) < 2 {
		return nil, fmt.Errorf("invalid response length")
	}

	if rsp[len(rsp)-2] != SW1_SUCCESS || rsp[len(rsp)-1] != SW2_SUCCESS {
		return nil, fmt.Errorf("read error: %02X %02X", rsp[len(rsp)-2], rsp[len(rsp)-1])
	}

	// Return only the first 4 bytes (the requested page)
	return rsp[:4], nil
}

// ReadPages reads multiple consecutive pages (returns 16 bytes)
func (n *NTAG) ReadPages(startPage byte) ([]byte, error) {
	// Fast read returns 4 pages (16 bytes) at once
	cmd := []byte{CLA_DIRECT_TRANSMIT, INS_READ_BINARY, 0x00, startPage, 0x10}

	rsp, err := n.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	if len(rsp) < 2 {
		return nil, fmt.Errorf("invalid response length")
	}

	if rsp[len(rsp)-2] != SW1_SUCCESS || rsp[len(rsp)-1] != SW2_SUCCESS {
		return nil, fmt.Errorf("read error: %02X %02X", rsp[len(rsp)-2], rsp[len(rsp)-1])
	}

	return rsp[:len(rsp)-2], nil
}

// WritePage writes a 4-byte page to the NTAG card
func (n *NTAG) WritePage(page byte, data []byte) error {
	if len(data) != 4 {
		return fmt.Errorf("data must be 4 bytes")
	}

	// WRITE command
	cmd := []byte{CLA_DIRECT_TRANSMIT, INS_UPDATE_BINARY, 0x00, page, 0x04}
	cmd = append(cmd, data...)

	rsp, err := n.card.Transmit(cmd)
	if err != nil {
		return fmt.Errorf("write failed: %v", err)
	}

	if len(rsp) != 2 || rsp[0] != SW1_SUCCESS || rsp[1] != SW2_SUCCESS {
		return fmt.Errorf("write error: %v", rsp)
	}

	return nil
}

// Authenticate performs password authentication
func (n *NTAG) Authenticate(password []byte) ([]byte, error) {
	if len(password) != 4 {
		return nil, fmt.Errorf("password must be 4 bytes")
	}

	// Direct transmit PWD_AUTH: FF 00 00 00 05 1B [4 bytes password]
	cmd := []byte{CLA_DIRECT_TRANSMIT, 0x00, 0x00, 0x00, 0x05, CMD_PWD_AUTH}
	cmd = append(cmd, password...)

	rsp, err := n.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	if len(rsp) < 2 {
		return nil, fmt.Errorf("invalid response length")
	}

	if rsp[len(rsp)-2] != SW1_SUCCESS || rsp[len(rsp)-1] != SW2_SUCCESS {
		return nil, fmt.Errorf("authentication error: %02X %02X", rsp[len(rsp)-2], rsp[len(rsp)-1])
	}

	// Return PACK (2 bytes)
	if len(rsp) >= 4 {
		return rsp[:2], nil
	}

	return nil, nil
}

// SetPassword configures password protection
// pwd: 4-byte password
// pack: 2-byte password acknowledge
// auth0: page from which password protection starts (0x00 = disabled)
// authLim: number of failed authentication attempts (0x00 = unlimited)
func (n *NTAG) SetPassword(pwd []byte, pack []byte, auth0 byte, authLim byte) error {
	if len(pwd) != 4 {
		return fmt.Errorf("password must be 4 bytes")
	}
	if len(pack) != 2 {
		return fmt.Errorf("PACK must be 2 bytes")
	}

	if n.chipType == nil {
		if _, err := n.DetectChipType(); err != nil {
			return fmt.Errorf("failed to detect chip type: %v", err)
		}
	}

	var pwdPage, packPage byte

	switch n.chipType.Name {
	case NTAG213:
		pwdPage = 0x2B  // Page 43
		packPage = 0x2C // Page 44
	case NTAG215:
		pwdPage = 0x85  // Page 133
		packPage = 0x86 // Page 134
	case NTAG216:
		pwdPage = 0xE5  // Page 229
		packPage = 0xE6 // Page 230
	default:
		return fmt.Errorf("unsupported chip type")
	}

	// Write PWD (4 bytes)
	if err := n.WritePage(pwdPage, pwd); err != nil {
		return fmt.Errorf("failed to write password: %v", err)
	}

	// Write PACK (2 bytes) + RFU (2 bytes, set to 0x00)
	packData := make([]byte, 4)
	copy(packData[0:2], pack)
	packData[2] = 0x00 // RFU
	packData[3] = 0x00 // RFU

	if err := n.WritePage(packPage, packData); err != nil {
		return fmt.Errorf("failed to write PACK: %v", err)
	}

	// Configure AUTH0 (starting page for authentication)
	// This is in the dynamic lock/reserved area
	var auth0Page byte
	switch n.chipType.Name {
	case NTAG213:
		auth0Page = 0x29 // Page 41
	case NTAG215:
		auth0Page = 0x83 // Page 131
	case NTAG216:
		auth0Page = 0xE3 // Page 227
	}

	// Read current configuration page
	configData, err := n.ReadPage(auth0Page)
	if err != nil {
		return fmt.Errorf("failed to read config page: %v", err)
	}

	// Modify AUTH0
	configData[3] = auth0

	if err := n.WritePage(auth0Page, configData); err != nil {
		return fmt.Errorf("failed to write AUTH0: %v", err)
	}

	// Set AUTHLIM in ACCESS page
	var accessPage byte
	switch n.chipType.Name {
	case NTAG213:
		accessPage = 0x2A // Page 42
	case NTAG215:
		accessPage = 0x84 // Page 132
	case NTAG216:
		accessPage = 0xE4 // Page 228
	}

	accessData, err := n.ReadPage(accessPage)
	if err != nil {
		return fmt.Errorf("failed to read access page: %v", err)
	}

	// Set AUTHLIM (bits 0-2 of byte 0)
	accessData[0] = (accessData[0] & 0xF8) | (authLim & 0x07)

	if err := n.WritePage(accessPage, accessData); err != nil {
		return fmt.Errorf("failed to write AUTHLIM: %v", err)
	}

	return nil
}

// RemovePassword disables password protection
func (n *NTAG) RemovePassword() error {
	if n.chipType == nil {
		if _, err := n.DetectChipType(); err != nil {
			return fmt.Errorf("failed to detect chip type: %v", err)
		}
	}

	var auth0Page byte
	switch n.chipType.Name {
	case NTAG213:
		auth0Page = 0x29
	case NTAG215:
		auth0Page = 0x83
	case NTAG216:
		auth0Page = 0xE3
	}

	// Read current configuration
	configData, err := n.ReadPage(auth0Page)
	if err != nil {
		return fmt.Errorf("failed to read config page: %v", err)
	}

	// Set AUTH0 to 0xFF (disables password protection)
	configData[3] = 0xFF

	if err := n.WritePage(auth0Page, configData); err != nil {
		return fmt.Errorf("failed to disable password: %v", err)
	}

	return nil
}

// DumpMemory reads all user-accessible pages
func (n *NTAG) DumpMemory() ([]byte, error) {
	if n.chipType == nil {
		if _, err := n.DetectChipType(); err != nil {
			return nil, fmt.Errorf("failed to detect chip type: %v", err)
		}
	}

	data := make([]byte, 0, n.chipType.TotalBytes)

	// Read all pages
	for page := byte(0); page < byte(n.chipType.TotalPages); page++ {
		pageData, err := n.ReadPage(page)
		if err != nil {
			// Some pages may not be readable
			return data, fmt.Errorf("failed to read page %d: %v", page, err)
		}
		data = append(data, pageData...)
	}

	return data, nil
}

// TryStandardPasswords attempts authentication with common passwords
func (n *NTAG) TryStandardPasswords() (string, []byte, error) {
	for name, cred := range DefaultPasswords {
		pack, err := n.Authenticate(cred.PWD)
		if err == nil {
			return name, pack, nil
		}
	}
	return "", nil, fmt.Errorf("no standard password matched")
}

// GetUserMemoryRange returns the start and end page numbers for user-writable memory
func (n *NTAG) GetUserMemoryRange() (start byte, end byte, err error) {
	if n.chipType == nil {
		if _, err := n.DetectChipType(); err != nil {
			return 0, 0, fmt.Errorf("failed to detect chip type: %v", err)
		}
	}

	switch n.chipType.Name {
	case NTAG213:
		return 4, 39, nil
	case NTAG215:
		return 4, 129, nil
	case NTAG216:
		return 4, 225, nil
	default:
		return 0, 0, fmt.Errorf("unknown chip type")
	}
}
