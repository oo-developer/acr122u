package desfire

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/ebfe/scard"
)

// DESFire card command codes
const (
	// Authentication commands
	CmdAuthenticateLegacy   = 0x0A // Legacy DES/3DES authentication
	CmdAuthenticateISO      = 0x1A // ISO 3DES authentication
	CmdAuthenticateAES      = 0xAA // AES authentication
	CmdAuthenticateEV2First = 0x71 // EV2 first authentication
	CmdAuthenticateEV2Non   = 0x77 // EV2 subsequent authentication

	// Application management
	CmdCreateApplication = 0xCA
	CmdDeleteApplication = 0xDA
	CmdGetApplicationIDs = 0x6A
	CmdSelectApplication = 0x5A
	CmdFormatPICC        = 0xFC
	CmdGetVersion        = 0x60
	CmdGetKeyVersion     = 0x64

	// File management
	CmdCreateStdDataFile      = 0xCD
	CmdCreateBackupDataFile   = 0xCB
	CmdCreateValueFile        = 0xCC
	CmdCreateLinearRecordFile = 0xC1
	CmdCreateCyclicRecordFile = 0xC0
	CmdDeleteFile             = 0xDF
	CmdGetFileIDs             = 0x6F
	CmdGetFileSettings        = 0xF5

	// Data manipulation
	CmdReadData          = 0xBD
	CmdWriteData         = 0x3D
	CmdGetValue          = 0x6C
	CmdCredit            = 0x0C
	CmdDebit             = 0xDC
	CmdLimitedCredit     = 0x1C
	CmdReadRecords       = 0xBB
	CmdWriteRecord       = 0x3B
	CmdCommitTransaction = 0xC7
	CmdAbortTransaction  = 0xA7

	// Key management
	CmdChangeKey         = 0xC4
	CmdChangeKeySettings = 0x54
	CmdGetKeySettings    = 0x45
	CmdSetConfiguration  = 0x5C

	// Additional frame
	CmdAdditionalFrame = 0xAF
)

// Status codes
const (
	StatusSuccess             = 0x00
	StatusNoChanges           = 0x0C
	StatusOutOfMemory         = 0x0E
	StatusIllegalCommand      = 0x1C
	StatusIntegrityError      = 0x1E
	StatusNoSuchKey           = 0x40
	StatusLengthError         = 0x7E
	StatusPermissionDenied    = 0x9D
	StatusParameterError      = 0x9E
	StatusApplicationNotFound = 0xA0
	StatusAuthenticationError = 0xAE
	StatusAdditionalFrame     = 0xAF
	StatusBoundaryError       = 0xBE
	StatusCommandAborted      = 0xCA
	StatusDuplicateError      = 0xDE
	StatusFileNotFound        = 0xF0
)

// Key types
const (
	KeyTypeDES    = 0x00
	KeyType3DES   = 0x01 // 2-key 3DES
	KeyType3K3DES = 0x02 // 3-key 3DES
	KeyTypeAES    = 0x03
)

// Communication modes
const (
	CommModePlain = 0x00
	CommModeMAC   = 0x01
	CommModeFull  = 0x03
)

// DESFire card structure
type DESFire struct {
	card    *scard.Card
	ctx     *scard.Context
	session *SessionKey
}

// SessionKey holds the session encryption keys
type SessionKey struct {
	keyType       byte
	key           []byte
	sessionKey    []byte
	sessionKeyMAC []byte
	iv            []byte
	cmdCounter    uint16
}

// NewDESFire creates a new DESFire card instance
func NewDESFire(card *scard.Card, ctx *scard.Context) *DESFire {
	return &DESFire{
		card: card,
		ctx:  ctx,
	}
}

// Transceive sends a command and receives response
func (df *DESFire) Transceive(cmd []byte) ([]byte, error) {
	// Wrap command in ISO 7816-4 APDU format
	apdu := make([]byte, 0, len(cmd)+5)
	apdu = append(apdu, 0x90)   // CLA
	apdu = append(apdu, cmd[0]) // INS (command code)
	apdu = append(apdu, 0x00)   // P1
	apdu = append(apdu, 0x00)   // P2

	if len(cmd) > 1 {
		apdu = append(apdu, byte(len(cmd)-1)) // Lc
		apdu = append(apdu, cmd[1:]...)       // Data
	} else {
		apdu = append(apdu, 0x00) // Lc = 0
	}

	apdu = append(apdu, 0x00) // Le

	response, err := df.card.Transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("transmit error: %w", err)
	}

	if len(response) < 2 {
		return nil, fmt.Errorf("response too short: %d bytes", len(response))
	}

	// Check status bytes (last 2 bytes)
	sw1 := response[len(response)-2]
	sw2 := response[len(response)-1]

	// Handle DESFire status codes wrapped in ISO 7816 format
	if sw1 == 0x91 {
		if sw2 != StatusSuccess && sw2 != StatusAdditionalFrame {
			return nil, fmt.Errorf("DESFire error: 0x%02X", sw2)
		}
		return response[:len(response)-2], nil
	}

	if sw1 == 0x90 && sw2 == 0x00 {
		// ISO success
		return response[:len(response)-2], nil
	}

	return nil, fmt.Errorf("card error: SW1=0x%02X SW2=0x%02X", sw1, sw2)
}

// GetVersion retrieves the card version information
func (df *DESFire) GetVersion() ([]byte, error) {
	// GetVersion requires 3 sequential commands
	var fullVersion []byte

	// First call
	resp, err := df.Transceive([]byte{CmdGetVersion})
	if err != nil {
		return nil, err
	}
	fullVersion = append(fullVersion, resp...)

	// Second call
	resp, err = df.Transceive([]byte{CmdAdditionalFrame})
	if err != nil {
		return nil, err
	}
	fullVersion = append(fullVersion, resp...)

	// Third call
	resp, err = df.Transceive([]byte{CmdAdditionalFrame})
	if err != nil {
		return nil, err
	}
	fullVersion = append(fullVersion, resp...)

	return fullVersion, nil
}

// GetUID retrieves the card UID from version info
func (df *DESFire) GetUID() ([]byte, error) {
	version, err := df.GetVersion()
	if err != nil {
		return nil, err
	}

	// UID is in the third part (bytes 14-20 of full version)
	if len(version) >= 21 {
		return version[14:21], nil
	}

	return nil, fmt.Errorf("version response too short")
}

// SelectApplication selects an application by AID
func (df *DESFire) SelectApplication(aid []byte) error {
	if len(aid) != 3 {
		return fmt.Errorf("AID must be 3 bytes")
	}

	cmd := append([]byte{CmdSelectApplication}, aid...)
	_, err := df.Transceive(cmd)
	return err
}

// GetApplicationIDs retrieves all application IDs
func (df *DESFire) GetApplicationIDs() ([][]byte, error) {
	resp, err := df.Transceive([]byte{CmdGetApplicationIDs})
	if err != nil {
		return nil, err
	}

	// Each AID is 3 bytes
	numApps := len(resp) / 3
	aids := make([][]byte, numApps)
	for i := 0; i < numApps; i++ {
		aids[i] = resp[i*3 : (i+1)*3]
	}

	return aids, nil
}

// AuthenticateAES performs AES authentication with the card
func (df *DESFire) AuthenticateAES(keyNo byte, key []byte) error {
	if len(key) != 16 {
		return fmt.Errorf("AES key must be 16 bytes")
	}

	// Step 1: Send authenticate command with key number
	cmd := []byte{CmdAuthenticateAES, keyNo}
	resp, err := df.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("authenticate step 1 failed: %w", err)
	}

	if len(resp) < 16 {
		return fmt.Errorf("encrypted RndB too short: %d bytes", len(resp))
	}

	encRndB := resp[:16]

	// Step 2: Decrypt RndB
	rndB, err := decryptAES(encRndB, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt RndB: %w", err)
	}

	// Step 3: Generate RndA
	rndA := make([]byte, 16)
	if _, err := rand.Read(rndA); err != nil {
		return fmt.Errorf("failed to generate RndA: %w", err)
	}

	// Step 4: Rotate RndB left by 1 byte
	rndBRotated := rotateLeft(rndB)

	// Step 5: Concatenate RndA + RndB' and encrypt
	data := append(rndA, rndBRotated...)
	encData, err := encryptAES(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Step 6: Send encrypted data
	cmd = append([]byte{CmdAdditionalFrame}, encData...)
	resp, err = df.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("authenticate step 2 failed: %w", err)
	}

	if len(resp) < 16 {
		return fmt.Errorf("encrypted RndA' too short: %d bytes", len(resp))
	}

	// Step 7: Decrypt and verify RndA'
	encRndARotated := resp[:16]
	rndARotatedDecrypted, err := decryptAES(encRndARotated, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt RndA': %w", err)
	}

	// Rotate RndA left to compare
	rndARotated := rotateLeft(rndA)
	if !bytes.Equal(rndARotated, rndARotatedDecrypted) {
		return fmt.Errorf("authentication failed: RndA mismatch")
	}

	// Generate session keys
	df.session = &SessionKey{
		keyType:    KeyTypeAES,
		key:        key,
		iv:         make([]byte, 16),
		cmdCounter: 0,
	}

	// Session key derivation for AES (simplified)
	df.session.sessionKey = make([]byte, 16)
	copy(df.session.sessionKey, key) // In production, derive properly from RndA and RndB

	return nil
}

// Authenticate3DES performs 3DES authentication (legacy)
func (df *DESFire) Authenticate3DES(keyNo byte, key []byte) error {
	if len(key) != 16 && len(key) != 24 {
		return fmt.Errorf("3DES key must be 16 or 24 bytes")
	}

	// Similar to AES but using 3DES and 8-byte blocks
	cmd := []byte{CmdAuthenticateISO, keyNo}
	resp, err := df.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("authenticate step 1 failed: %w", err)
	}

	if len(resp) < 8 {
		return fmt.Errorf("encrypted RndB too short: %d bytes", len(resp))
	}

	encRndB := resp[:8]

	// Decrypt RndB
	rndB, err := decrypt3DES(encRndB, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt RndB: %w", err)
	}

	// Generate RndA (8 bytes for DES/3DES)
	rndA := make([]byte, 8)
	if _, err := rand.Read(rndA); err != nil {
		return fmt.Errorf("failed to generate RndA: %w", err)
	}

	// Rotate RndB left by 1 byte
	rndBRotated := rotateLeft(rndB)

	// Concatenate and encrypt
	data := append(rndA, rndBRotated...)
	encData, err := encrypt3DES(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Send encrypted data
	cmd = append([]byte{CmdAdditionalFrame}, encData...)
	resp, err = df.Transceive(cmd)
	if err != nil {
		return fmt.Errorf("authenticate step 2 failed: %w", err)
	}

	// Verify response
	if len(resp) < 8 {
		return fmt.Errorf("encrypted RndA' too short: %d bytes", len(resp))
	}

	rndARotatedDecrypted, err := decrypt3DES(resp[:8], key)
	if err != nil {
		return fmt.Errorf("failed to decrypt RndA': %w", err)
	}

	rndARotated := rotateLeft(rndA)
	if !bytes.Equal(rndARotated, rndARotatedDecrypted) {
		return fmt.Errorf("authentication failed: RndA mismatch")
	}

	df.session = &SessionKey{
		keyType:    KeyType3DES,
		key:        key,
		iv:         make([]byte, 8),
		cmdCounter: 0,
	}

	return nil
}

// CreateApplication creates a new application
func (df *DESFire) CreateApplication(aid []byte, keySetting byte, numKeys byte) error {
	if len(aid) != 3 {
		return fmt.Errorf("AID must be 3 bytes")
	}

	cmd := []byte{CmdCreateApplication}
	cmd = append(cmd, aid...)
	cmd = append(cmd, keySetting)
	cmd = append(cmd, numKeys)

	_, err := df.Transceive(cmd)
	return err
}

// DeleteApplication deletes an application
func (df *DESFire) DeleteApplication(aid []byte) error {
	if len(aid) != 3 {
		return fmt.Errorf("AID must be 3 bytes")
	}

	cmd := append([]byte{CmdDeleteApplication}, aid...)
	_, err := df.Transceive(cmd)
	return err
}

// ReadData reads data from a standard data file
func (df *DESFire) ReadData(fileNo byte, offset int, length int) ([]byte, error) {
	cmd := []byte{CmdReadData, fileNo}

	// Add offset (3 bytes, little-endian)
	offsetBytes := make([]byte, 3)
	binary.LittleEndian.PutUint32(append(offsetBytes, 0), uint32(offset))
	cmd = append(cmd, offsetBytes[:3]...)

	// Add length (3 bytes, little-endian)
	lengthBytes := make([]byte, 3)
	binary.LittleEndian.PutUint32(append(lengthBytes, 0), uint32(length))
	cmd = append(cmd, lengthBytes[:3]...)

	return df.Transceive(cmd)
}

// WriteData writes data to a standard data file
func (df *DESFire) WriteData(fileNo byte, offset int, data []byte) error {
	cmd := []byte{CmdWriteData, fileNo}

	// Add offset (3 bytes, little-endian)
	offsetBytes := make([]byte, 3)
	binary.LittleEndian.PutUint32(append(offsetBytes, 0), uint32(offset))
	cmd = append(cmd, offsetBytes[:3]...)

	// Add length (3 bytes, little-endian)
	lengthBytes := make([]byte, 3)
	binary.LittleEndian.PutUint32(append(lengthBytes, 0), uint32(len(data)))
	cmd = append(cmd, lengthBytes[:3]...)

	// Add data
	cmd = append(cmd, data...)

	_, err := df.Transceive(cmd)
	return err
}

// Helper functions for cryptography

func encryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pad data to block size
	data = padData(data, aes.BlockSize)

	ciphertext := make([]byte, len(data))
	iv := make([]byte, aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}

func decryptAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(data))
	iv := make([]byte, aes.BlockSize)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	return plaintext, nil
}

func encrypt3DES(data []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var err error

	if len(key) == 16 {
		// 2-key 3DES
		block, err = des.NewTripleDESCipher(key)
	} else if len(key) == 24 {
		// 3-key 3DES
		block, err = des.NewTripleDESCipher(key)
	} else {
		return nil, fmt.Errorf("invalid key length for 3DES")
	}

	if err != nil {
		return nil, err
	}

	data = padData(data, des.BlockSize)
	ciphertext := make([]byte, len(data))
	iv := make([]byte, des.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}

func decrypt3DES(data []byte, key []byte) ([]byte, error) {
	var block cipher.Block
	var err error

	if len(key) == 16 {
		block, err = des.NewTripleDESCipher(key)
	} else if len(key) == 24 {
		block, err = des.NewTripleDESCipher(key)
	} else {
		return nil, fmt.Errorf("invalid key length for 3DES")
	}

	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(data))
	iv := make([]byte, des.BlockSize)

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, data)

	return plaintext, nil
}

func padData(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
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
