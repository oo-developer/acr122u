package database

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CardEntry represents a single card definition
type CardEntry struct {
	ATR  string
	Name string
}

// CardDatabase holds all card definitions
type CardDatabase struct {
	entries []CardEntry
}

// NewCardDatabase creates a new card database
func NewCardDatabase() *CardDatabase {
	return &CardDatabase{
		entries: make([]CardEntry, 0),
	}
}

// GetDefaultSearchPaths returns common locations for smartcard_list.txt
func GetDefaultSearchPaths() []string {
	return []string{
		"/usr/share/pcsc/smartcard_list.txt",
		"/usr/local/share/pcsc/smartcard_list.txt",
		"/etc/pcsc/smartcard_list.txt",
		"/opt/pcsc/smartcard_list.txt",
		"./smartcard_list.txt",
		"../smartcard_list.txt",
		"../../smartcard_list.txt",
		filepath.Join(os.Getenv("HOME"), ".pcsc", "smartcard_list.txt"),
		filepath.Join(os.Getenv("HOME"), ".local", "share", "pcsc", "smartcard_list.txt"),
	}
}

// ProbeForFile searches for smartcard_list.txt in common locations
func ProbeForFile() (string, error) {
	paths := GetDefaultSearchPaths()

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("smartcard_list.txt not found in any standard location")
}

// LoadFromFile loads card definitions from smartcard_list.txt
func (db *CardDatabase) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentATR string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if this is an ATR line (starts with hex digits)
		if len(line) > 0 && isHexLine(line) {
			// Remove spaces and store ATR
			currentATR = strings.ReplaceAll(line, " ", "")
			currentATR = strings.ToUpper(currentATR)

			// Read next line for card name
			if scanner.Scan() {
				name := strings.TrimSpace(scanner.Text())
				if name != "" {
					db.entries = append(db.entries, CardEntry{
						ATR:  currentATR,
						Name: name,
					})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	return nil
}

// LoadWithProbe attempts to find and load smartcard_list.txt automatically
func (db *CardDatabase) LoadWithProbe() (string, error) {
	path, err := ProbeForFile()
	if err != nil {
		return "", err
	}

	err = db.LoadFromFile(path)
	if err != nil {
		return "", fmt.Errorf("found file at %s but failed to load: %w", path, err)
	}

	return path, nil
}

// isHexLine checks if a line starts with hex characters
func isHexLine(line string) bool {
	// Remove spaces and check if it's valid hex
	cleaned := strings.ReplaceAll(line, " ", "")
	if len(cleaned) == 0 {
		return false
	}

	// Check first few characters
	for i := 0; i < len(cleaned) && i < 6; i++ {
		c := cleaned[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Detect finds the card name based on ATR bytes
func (db *CardDatabase) Detect(atr []byte) string {
	atrHex := strings.ToUpper(hex.EncodeToString(atr))

	for _, entry := range db.entries {
		if entry.ATR == atrHex {
			return entry.Name
		}
	}

	return "Unknown Card"
}

// DetectWithPartialMatch finds cards that match the beginning of the ATR
func (db *CardDatabase) DetectWithPartialMatch(atr []byte, minMatchBytes int) []string {
	atrHex := strings.ToUpper(hex.EncodeToString(atr))
	matches := []string{}

	minMatchLen := minMatchBytes * 2 // Convert bytes to hex characters

	for _, entry := range db.entries {
		// Check if we have enough data to compare
		matchLen := len(atrHex)
		if len(entry.ATR) < matchLen {
			matchLen = len(entry.ATR)
		}

		if matchLen >= minMatchLen && strings.HasPrefix(entry.ATR, atrHex[:matchLen]) {
			matches = append(matches, entry.Name)
		}
	}

	return matches
}

// Count returns the number of loaded card definitions
func (db *CardDatabase) Count() int {
	return len(db.entries)
}

// ListAll prints all loaded card definitions
func (db *CardDatabase) ListAll() {
	for i, entry := range db.entries {
		fmt.Printf("%d. ATR: %s\n   Name: %s\n\n", i+1, entry.ATR, entry.Name)
	}
}

// GetEntries returns all card entries
func (db *CardDatabase) GetEntries() []CardEntry {
	return db.entries
}

// FindByName searches for cards by name (case-insensitive partial match)
func (db *CardDatabase) FindByName(name string) []CardEntry {
	results := []CardEntry{}
	searchTerm := strings.ToLower(name)

	for _, entry := range db.entries {
		if strings.Contains(strings.ToLower(entry.Name), searchTerm) {
			results = append(results, entry)
		}
	}

	return results
}
