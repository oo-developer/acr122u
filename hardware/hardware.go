package hardware

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ebfe/scard"
)

const (
	MIFARE_CLASSIK_1K = "MIFARE Classic 1K"
	MIFARE_CLASSIK_4K = "MIFARE Classic 4K"
	MIFARE_MINI       = "MIFARE Mini"
	MIFARE_ULTRALIGHT = "MIFARE Ultralight/NTAG203/213"
	NTAG              = "NTAG215/216"
	MIFARE_DESFIRE    = "MIFARE DESFire EV1/EV2/EV3"
	MIFARE_PLUS_SE_2K = "MIFARE Plus SE 2K"
	MIFARE_PLUS_SE_4K = "MIFARE Plus SE 4K"
	TOPAZ_JEWEL       = "Topaz/Jewel"
	FELI_CA           = "FeliCa"
)

type CardInfo struct {
	Type        string
	UID         []byte
	ATR         []byte // Answer to Reset
	SAK         byte   // Select Acknowledge
	ATQA        []byte // Answer to Request Type A
	Capacity    int    // Storage capacity in bytes
	BlockCount  int    // Number of blocks
	SectorCount int    // Number of sectors
	Protocol    string // Communication protocol
}

type Reader struct {
	ctx    *scard.Context
	card   *scard.Card
	reader string
}

// NewReader initializes a new hardware
func NewReader() (*Reader, error) {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("failed to establish context: %v", err)
	}

	return &Reader{
		ctx: ctx,
	}, nil
}

func (m *Reader) Ctx() *scard.Context {
	return m.ctx
}

func (m *Reader) Card() *scard.Card {
	return m.card
}

func (m *Reader) Reader() string {
	return m.reader
}

// Close releases the hardware resources
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

// Connect connects to the first available hardware with a card
func (m *Reader) Connect() error {
	if m.reader == "" {
		return fmt.Errorf("no hardware selected, use: UseReader(hardware string)")
	}
	card, err := m.ctx.Connect(m.reader, scard.ShareShared, scard.ProtocolT0|scard.ProtocolT1)
	if err != nil {
		return fmt.Errorf("failed to connect to hardware: %v", err)
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

func (m *Reader) ReadCardInfo() (*CardInfo, error) {
	if m.card == nil {
		return nil, fmt.Errorf("not connected to card")
	}

	sak, atqa, sizeInBytes, err := m.getCardAttributes()
	if err != nil {
		return nil, err
	}

	status, err := m.card.Status()
	if err != nil {
		return nil, err
	}
	protocol := "Unknown"
	switch status.ActiveProtocol {
	case scard.ProtocolT0:
		protocol = "T=0"
	case scard.ProtocolT1:
		protocol = "T=1"
	default:
		protocol = "Unknown"
	}
	cardType, err := m.getCardType(atqa, sak, sizeInBytes)

	uid, err := m.GetUID()
	if err != nil {
		return nil, fmt.Errorf("failed to get UID: %v", err)
	}
	info := &CardInfo{
		UID:      uid,
		Type:     cardType,
		ATR:      status.Atr,
		SAK:      sak,
		ATQA:     atqa,
		Protocol: protocol,
		Capacity: sizeInBytes,
	}
	return info, nil
}

func (m *Reader) getCardAttributes() (sak byte, atqa []byte, sizeInBytes int, err error) {
	if ok, size := m.tryClassic(); ok {
		sizeInBytes = size
		if size == 1024 {
			sak = 0x08
			atqa = []byte{0x00, 0x04}
		} else {
			sak = 0x18
			atqa = []byte{0x00, 0x02}
		}
		return sak, atqa, sizeInBytes, nil
	}
	if ok, size := m.tryNTAG(); ok {
		sizeInBytes = size
		if (size > 480 && size <= 504) || size == 888 {
			sak = 0x00
			atqa = []byte{0x00, 0x00}
		} else if size == 144 {
			sak = 0x44
			atqa = []byte{0x00, 0x44}
		}
		return sak, atqa, sizeInBytes, nil
	}
	if m.tryUltralight() {
		sak = 0x00
		atqa = []byte{0x00, 0x44}
		return sak, atqa, 0, nil
	}
	selectAll := []byte{0xFF, 0xCA, 0x00, 0x00, 0x00}
	resp, err := m.card.Transmit(selectAll)
	if err != nil {
		return sak, atqa, 0, fmt.Errorf("failed to transmit: %v", err)
	}
	if len(resp) < 4 || !bytes.Equal(resp[len(resp)-2:], []byte{0x90, 0x00}) {
		return sak, atqa, 0, fmt.Errorf("invalid response length")
	}
	atqa, sak = resp[0:2], resp[2]
	return sak, atqa, 0, nil
}

func (m *Reader) getCardType(atqa []byte, sak byte, sizeInBytes int) (string, error) {

	type cardType struct {
		ATQA    [2]byte
		SAK     byte
		Name    string
		Details string
	}
	cardTypes := []cardType{
		{[2]byte{0x00, 0x04}, 0x08, MIFARE_CLASSIK_1K, "1KB, CRYPTO1"},
		{[2]byte{0x00, 0x02}, 0x18, MIFARE_CLASSIK_4K, "4KB, CRYPTO1"},
		{[2]byte{0x00, 0x44}, 0x09, MIFARE_MINI, "320B, CRYPTO1"},
		{[2]byte{0x00, 0x44}, 0x00, MIFARE_ULTRALIGHT, "Check CC for specifics"},
		{[2]byte{0x00, 0x00}, 0x00, NTAG, "Check CC: 504B/888B"},
		{[2]byte{0x03, 0x44}, 0x20, MIFARE_DESFIRE, "2-16KB, AES"},
		{[2]byte{0x00, 0x04}, 0x0C, MIFARE_PLUS_SE_2K, "2KB, CRYPTO1/AES"},
		{[2]byte{0x00, 0x02}, 0x1C, MIFARE_PLUS_SE_4K, "4KB, CRYPTO1/AES"},
		{[2]byte{0x0C, 0x00}, 0x00, TOPAZ_JEWEL, "96-512B, no auth"},
		{[2]byte{0x00, 0x43}, 0x11, FELI_CA, "Variable, FeliCa-specific"},
	}

	for _, ct := range cardTypes {
		if bytes.Equal(atqa, ct.ATQA[:]) && sak == ct.SAK {
			if ct.Name == NTAG {
				ct.Details = fmt.Sprintf("%dB", sizeInBytes)
			}
			return fmt.Sprintf("%s (%s)", ct.Name, ct.Details), nil
		}
	}
	return fmt.Sprintf("Unknown (ATQA=%s, SAK=%02x)", hex.EncodeToString(atqa), sak), nil
}

func (m *Reader) tryClassic() (bool, int) {

	defaultKey := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	err := m.classicLoadKey(0x00, defaultKey)
	if err != nil {
		return false, 0
	}
	keyTypeA := byte(0x60)
	err = m.classicAuthenticate(0x40, keyTypeA, 0x00)
	if err == nil {
		return true, 4096
	}
	err = m.classicAuthenticate(0x00, keyTypeA, 0x00)
	if err == nil {
		return true, 1024
	}
	return false, 0
}

func (m *Reader) classicLoadKey(keyNumber byte, key []byte) error {
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
func (m *Reader) classicAuthenticate(block byte, keyType byte, keyNumber byte) error {
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

func (m *Reader) tryUltralight() bool {
	CmdRead := byte(0x30)
	cmd := []byte{CmdRead, 4}
	response, err := m.card.Transmit(cmd)
	if err != nil {
		return false
	}
	if len(response) < 2 {
		return false
	}
	return true
}

func (m *Reader) tryNTAG() (bool, int) {
	page3, err := m.card.Transmit([]byte{0xFF, 0xB0, 0x00, 0x03, 0x04})
	if err != nil {
		return false, 0
	}
	if len(page3) < 4 {
		return false, 0
	}
	if !bytes.Equal(page3[4:], []byte{0x90, 0x00}) {
		return false, 0
	}
	cc := page3[:4]
	switch {
	case bytes.Equal(cc, []byte{0xE1, 0x10, 0x12, 0x00}):
		return true, 144 // "NTAG213 (144 Bytes)"
	case bytes.Equal(cc, []byte{0xE1, 0x10, 0x3F, 0x00}):
		return true, 504 // "NTAG215 (504 Bytes)"
	case bytes.Equal(cc, []byte{0xE1, 0x10, 0x6D, 0x00}):
		return true, 888 // "NTAG216 (888 Bytes)"
	case bytes.Equal(cc, []byte{0xE1, 0x10, 0x3E, 0x00}):
		return true, 496 // "NTAG215 (496 Bytes)"
	default:
		return false, 0
	}
}
