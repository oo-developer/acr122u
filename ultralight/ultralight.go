package ultralight

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/ebfe/scard"
	"github.com/oo-developer/acr122u/hardware"
)

// Ultralight C command codes
const (
	CmdRead               = 0x30 // Read 4 pages (16 bytes)
	CmdWrite              = 0xA2 // Write 1 page (4 bytes)
	CmdCompatibilityWrite = 0xA0 // Compatibility write
	CmdAuthenticate1      = 0x1A // Authentication step 1
	CmdAuthenticate2      = 0xAF // Authentication step 2
	CmdHalt               = 0x50 // Halt card
)

// Memory layout constants
const (
	PageSize        = 4  // 4 bytes per page
	TotalPages      = 48 // Total 48 pages (192 bytes)
	UserMemoryStart = 4  // User memory starts at page 4
	UserMemoryEnd   = 39 // User memory ends at page 39
	LockBytes0Page  = 2  // Lock bytes 0-1 location
	LockBytes1Page  = 40 // Lock bytes 2-3 location
	OTPPage         = 3  // OTP area (page 3)
	CounterPage     = 41 // 16-bit counter
	Auth0Page       = 42 // Authentication config (AUTH0)
	Auth1Page       = 43 // Authentication config (AUTH1)
	KeyPage         = 44 // 3DES key starts at page 44 (0x2C)
)

// Status codes
const (
	StatusOK  = 0x00
	StatusNAK = 0x00 // NAK in response
	StatusACK = 0x0A // ACK response (4 bits)
)

// UltralightC card structure
type UltralightC struct {
	card          *scard.Card
	ctx           *scard.Context
	reader        string
	authenticated bool
	key           []byte
	uid           []byte
}

// NewUltralightC creates a new Ultralight C card instance
func NewUltralightC(reader *hardware.Reader) *UltralightC {
	return &UltralightC{
		card:          reader.Card(),
		ctx:           reader.Ctx(),
		reader:        reader.Reader(),
		authenticated: false,
	}
}

// Transceive sends a command and receives response (raw ISO 14443-3A)
func (uc *UltralightC) Transceive(cmd []byte) ([]byte, error) {
	response, err := uc.card.Transmit(cmd)
	if err != nil {
		return nil, fmt.Errorf("transmit error: %w", err)
	}

	if len(response) < 2 {
		return nil, fmt.Errorf("response too short: %d bytes", len(response))
	}

	// Remove status bytes if present (some readers add SW1 SW2)
	if len(response) >= 2 {
		lastTwo := response[len(response)-2:]
		if lastTwo[0] == 0x90 && lastTwo[1] == 0x00 {
			return response[:len(response)-2], nil
		}
	}

	return response, nil
}

// GetUID retrieves the card UID
// UID is stored in pages 0-1 (first 7 bytes)
func (uc *UltralightC) GetUID() ([]byte, error) {
	// Read page 0 (contains first part of UID)
	data, err := uc.ReadPages(0, 2)
	if err != nil {
		return nil, err
	}

	if len(data) < 8 {
		return nil, fmt.Errorf("insufficient data for UID")
	}

	// UID is 7 bytes:
	// Page 0: UID0 UID1 UID2 BCC0
	// Page 1: UID3 UID4 UID5 UID6
	uid := make([]byte, 7)
	uid[0] = data[0]
	uid[1] = data[1]
	uid[2] = data[2]
	// Skip BCC0 at data[3]
	copy(uid[3:], data[4:8])

	uc.uid = uid
	return uid, nil
}

// ReadPage reads a single page (4 bytes)
// Note: Ultralight C actually returns 4 pages (16 bytes) per read
func (uc *UltralightC) ReadPage(pageAddr byte) ([]byte, error) {
	if pageAddr >= TotalPages {
		return nil, fmt.Errorf("page address out of range: %d", pageAddr)
	}

	cmd := []byte{CmdRead, pageAddr}
	resp, err := uc.Transceive(cmd)
	if err != nil {
		return nil, err
	}

	// Read returns 16 bytes (4 pages), extract the requested page
	if len(resp) < 16 {
		return nil, fmt.Errorf("unexpected response length: %d", len(resp))
	}

	return resp[0:4], nil
}

// ReadPages reads multiple consecutive pages
// Returns 16 bytes (4 pages) per read command
func (uc *UltralightC) ReadPages(startPage byte, numPages int) ([]byte, error) {
	if startPage >= TotalPages {
		return nil, fmt.Errorf("start page out of range: %d", startPage)
	}

	result := make([]byte, 0, numPages*PageSize)

	for i := 0; i < numPages; i += 4 {
		currentPage := startPage + byte(i)
		if currentPage >= TotalPages {
			break
		}

		cmd := []byte{CmdRead, currentPage}
		resp, err := uc.Transceive(cmd)
		if err != nil {
			return nil, fmt.Errorf("error reading page %d: %w", currentPage, err)
		}

		if len(resp) < 16 {
			return nil, fmt.Errorf("unexpected response length: %d", len(resp))
		}

		// Each read returns 4 pages (16 bytes)
		pagesNeeded := numPages - i
		if pagesNeeded > 4 {
			pagesNeeded = 4
		}

		result = append(result, resp[:pagesNeeded*PageSize]...)
	}

	return result, nil
}

// WritePage writes data to a single page (4 bytes)
func (uc *UltralightC) WritePage(pageAddr byte, data []byte) error {
	if pageAddr >= TotalPages {
		return fmt.Errorf("page address out of range: %d", pageAddr)
	}

	if len(data) != 4 {
		return fmt.Errorf("data must be exactly 4 bytes, got %d", len(data))
	}

	cmd := make([]byte, 6)
	cmd[0] = CmdWrite
	cmd[1] = pageAddr
	copy(cmd[2:], data)

	resp, err := uc.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	// Check for ACK (0x0A) - it's a 4-bit response
	if len(resp) > 0 && (resp[0] == 0x0A || resp[0] == 0x00) {
		return nil
	}

	return fmt.Errorf("write failed: unexpected response %X", resp)
}

// Authenticate performs 3DES authentication with the card
// The default key is "BREAKMEIFYOUCAN!" (16 bytes)
func (uc *UltralightC) Authenticate(key []byte) error {
	if len(key) != 16 {
		return fmt.Errorf("key must be 16 bytes for 3DES, got %d", len(key))
	}

	// Step 1: Send authentication command (0x1A 0x00)
	cmd := []byte{CmdAuthenticate1, 0x00}
	resp, err := uc.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("authentication step 1 failed: %w", err)
	}

	// Response should be 8 bytes (encrypted RndB)
	if len(resp) < 8 {
		return fmt.Errorf("authentication step 1: expected 8 bytes, got %d", len(resp))
	}

	encRndB := resp[:8]

	// Step 2: Decrypt RndB using the key
	rndB, err := decrypt3DES(encRndB, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt RndB: %w", err)
	}

	// Step 3: Generate random RndA (8 bytes)
	rndA := make([]byte, 8)
	if _, err := rand.Read(rndA); err != nil {
		return fmt.Errorf("failed to generate RndA: %w", err)
	}

	// Step 4: Rotate RndB left by 1 byte
	rndBRotated := rotateLeft(rndB)

	// Step 5: Concatenate RndA + RndB' (16 bytes total)
	data := append(rndA, rndBRotated...)

	// Step 6: Encrypt the concatenated data
	encData, err := encrypt3DES(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Step 7: Send encrypted data (0xAF + encrypted data)
	cmd = append([]byte{CmdAuthenticate2}, encData...)
	resp, err = uc.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("authentication step 2 failed: %w", err)
	}

	// Step 8: Response should be 8 bytes (encrypted RndA')
	if len(resp) < 8 {
		return fmt.Errorf("authentication step 2: expected 8 bytes, got %d", len(resp))
	}

	// Step 9: Decrypt and verify RndA'
	encRndARotated := resp[:8]
	rndARotatedDecrypted, err := decrypt3DES(encRndARotated, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt RndA': %w", err)
	}

	// Step 10: Rotate RndA left to compare
	rndARotated := rotateLeft(rndA)

	if !bytes.Equal(rndARotated, rndARotatedDecrypted) {
		return fmt.Errorf("authentication failed: RndA mismatch")
	}

	// Authentication successful
	uc.authenticated = true
	uc.key = key

	return nil
}

// IsAuthenticated returns whether the card is authenticated
func (uc *UltralightC) IsAuthenticated() bool {
	return uc.authenticated
}

// ReadUserMemory reads all user memory (pages 4-39)
func (uc *UltralightC) ReadUserMemory() ([]byte, error) {
	numPages := UserMemoryEnd - UserMemoryStart + 1
	return uc.ReadPages(UserMemoryStart, numPages)
}

// WriteUserMemory writes data to user memory starting at specified page
func (uc *UltralightC) WriteUserMemory(startPage byte, data []byte) error {
	if startPage < UserMemoryStart || startPage > UserMemoryEnd {
		return fmt.Errorf("start page must be between %d and %d", UserMemoryStart, UserMemoryEnd)
	}

	// Write page by page
	for i := 0; i < len(data); i += 4 {
		pageAddr := startPage + byte(i/4)
		if pageAddr > UserMemoryEnd {
			return fmt.Errorf("data exceeds user memory boundary")
		}

		pageData := make([]byte, 4)
		copy(pageData, data[i:])

		if err := uc.WritePage(pageAddr, pageData); err != nil {
			return fmt.Errorf("error writing page %d: %w", pageAddr, err)
		}
	}

	return nil
}

// GetCounter reads the 16-bit counter value
func (uc *UltralightC) GetCounter() (uint16, error) {
	data, err := uc.ReadPage(CounterPage)
	if err != nil {
		return 0, err
	}

	// Counter is stored in first 2 bytes, little-endian
	counter := binary.LittleEndian.Uint16(data[0:2])
	return counter, nil
}

// IncrementCounter increments the counter (one-way operation)
func (uc *UltralightC) IncrementCounter() error {
	// Read current counter
	current, err := uc.GetCounter()
	if err != nil {
		return err
	}

	// Increment
	newValue := current + 1

	// Write back (note: this is a one-way counter)
	data := make([]byte, 4)
	binary.LittleEndian.PutUint16(data, newValue)

	return uc.WritePage(CounterPage, data)
}

// GetAuthConfig reads the authentication configuration
// Returns (AUTH0, AUTH1)
func (uc *UltralightC) GetAuthConfig() (byte, byte, error) {
	auth0Data, err := uc.ReadPage(Auth0Page)
	if err != nil {
		return 0, 0, err
	}

	auth1Data, err := uc.ReadPage(Auth1Page)
	if err != nil {
		return 0, 0, err
	}

	return auth0Data[0], auth1Data[0], nil
}

// SetAuthConfig sets authentication requirements
// auth0: First page requiring authentication (0x03-0x30)
// auth1: Write access restriction (0x00 = write requires auth, 0x01 = write always allowed)
func (uc *UltralightC) SetAuthConfig(auth0, auth1 byte) error {
	if !uc.authenticated {
		return fmt.Errorf("authentication required to change auth config")
	}

	// Write AUTH0
	auth0Data := []byte{auth0, 0x00, 0x00, 0x00}
	if err := uc.WritePage(Auth0Page, auth0Data); err != nil {
		return fmt.Errorf("failed to write AUTH0: %w", err)
	}

	// Write AUTH1
	auth1Data := []byte{auth1, 0x00, 0x00, 0x00}
	if err := uc.WritePage(Auth1Page, auth1Data); err != nil {
		return fmt.Errorf("failed to write AUTH1: %w", err)
	}

	return nil
}

// ChangeKey changes the 3DES authentication key
// The key must be written in reverse byte order!
func (uc *UltralightC) ChangeKey(newKey []byte) error {
	if len(newKey) != 16 {
		return fmt.Errorf("key must be 16 bytes")
	}

	if !uc.authenticated {
		return fmt.Errorf("authentication required to change key")
	}

	// Key is stored in pages 44-47 (0x2C-0x2F)
	// IMPORTANT: Key must be written in REVERSE byte order
	// If key is 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
	// Write:     07 06 05 04 03 02 01 00 0F 0E 0D 0C 0B 0A 09 08

	reversedKey := make([]byte, 16)
	for i := 0; i < 8; i++ {
		reversedKey[i] = newKey[7-i]
		reversedKey[i+8] = newKey[15-i]
	}

	// Write 4 pages (each 4 bytes)
	for i := 0; i < 4; i++ {
		pageAddr := KeyPage + byte(i)
		pageData := reversedKey[i*4 : (i+1)*4]

		if err := uc.WritePage(pageAddr, pageData); err != nil {
			return fmt.Errorf("failed to write key page %d: %w", pageAddr, err)
		}
	}

	uc.key = newKey
	return nil
}

// ReadKey reads the current key from the card (for verification)
// Note: This only works if the pages are not protected
func (uc *UltralightC) ReadKey() ([]byte, error) {
	// Read pages 44-47
	keyData := make([]byte, 16)
	for i := 0; i < 4; i++ {
		pageAddr := KeyPage + byte(i)
		page, err := uc.ReadPage(pageAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to read key page %d: %w", pageAddr, err)
		}
		copy(keyData[i*4:], page)
	}

	// Reverse the byte order to get actual key
	actualKey := make([]byte, 16)
	for i := 0; i < 8; i++ {
		actualKey[7-i] = keyData[i]
		actualKey[15-i] = keyData[i+8]
	}

	return actualKey, nil
}

// DefaultKey returns the default Ultralight C key "BREAKMEIFYOUCAN!"
func DefaultKey() []byte {
	return []byte{
		0x42, 0x52, 0x45, 0x41, 0x4B, 0x4D, 0x45, 0x49,
		0x46, 0x59, 0x4F, 0x55, 0x43, 0x41, 0x4E, 0x21,
	}
}

// Helper functions for cryptography

func encrypt3DES(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes for 2-key 3DES")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad data to block size if necessary
	if len(data)%8 != 0 {
		padding := 8 - (len(data) % 8)
		data = append(data, bytes.Repeat([]byte{0}, padding)...)
	}

	ciphertext := make([]byte, len(data))
	iv := make([]byte, 8) // Zero IV

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}

func decrypt3DES(data []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes for 2-key 3DES")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%8 != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(data))
	iv := make([]byte, 8) // Zero IV

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	return plaintext, nil
}

func rotateLeft(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	rotated := make([]byte, len(data))
	copy(rotated, data[1:])
	rotated[len(data)-1] = data[0]
	return rotated
}
