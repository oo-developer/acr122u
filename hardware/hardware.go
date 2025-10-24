package hardware

import (
	"fmt"
	"time"

	"github.com/ebfe/scard"
	"github.com/oo-developer/acr122u/database"
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

func (r *Reader) Ctx() *scard.Context {
	return r.ctx
}

func (r *Reader) Card() *scard.Card {
	return r.card
}

func (r *Reader) Reader() string {
	return r.reader
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

func (m *Reader) DetectCardType() (*CardInfo, error) {
	if m.card == nil {
		return nil, fmt.Errorf("not connected to card")
	}

	sak, atqa := m.getCardAttributes()

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
	db := database.NewCardDatabase()
	db.LoadWithProbe()
	cardName := db.Detect(status.Atr)

	uid, err := m.GetUID()
	if err != nil {
		return nil, fmt.Errorf("failed to get UID: %v", err)
	}
	info := &CardInfo{
		UID:      uid,
		Type:     cardName,
		ATR:      status.Atr,
		SAK:      sak,
		ATQA:     atqa,
		Protocol: protocol,
	}
	info.UID = uid

	return info, nil
}

func (m *Reader) getCardAttributes() (sak byte, atqa []byte) {
	// This is a simplified version - actual implementation may vary by hardware
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
