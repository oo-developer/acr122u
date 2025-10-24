package samples

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ebfe/scard"
	"github.com/oo-developer/acr122u/ultralight"
)

func main() {
	// Establish context
	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Fatal("Error establishing context:", err)
	}
	defer ctx.Release()

	// List available readers
	readers, err := ctx.ListReaders()
	if err != nil {
		log.Fatal("Error listing readers:", err)
	}

	if len(readers) == 0 {
		log.Fatal("No smart card readers found")
	}

	fmt.Printf("Using hardware: %s\n", readers[0])

	// Connect to card
	card, err := ctx.Connect(readers[0], scard.ShareShared, scard.ProtocolAny)
	if err != nil {
		log.Fatal("Error connecting to card:", err)
	}
	defer card.Disconnect(scard.LeaveCard)

	// Create Ultralight C instance
	uc := ultralight.NewUltralightC(card, ctx)

	// Example 1: Get card UID
	fmt.Println("\n=== Getting Card UID ===")
	uid, err := uc.GetUID()
	if err != nil {
		log.Printf("Error getting UID: %v", err)
	} else {
		fmt.Printf("Card UID: %s\n", hex.EncodeToString(uid))
	}

	// Example 2: Read a page without authentication
	fmt.Println("\n=== Reading Page (No Authentication) ===")
	pageData, err := uc.ReadPage(4) // Read page 4
	if err != nil {
		log.Printf("Error reading page: %v", err)
	} else {
		fmt.Printf("Page 4 data: %s\n", hex.EncodeToString(pageData))
	}

	// Example 3: Read multiple pages
	fmt.Println("\n=== Reading Multiple Pages ===")
	userData, err := uc.ReadPages(4, 8) // Read 8 pages starting from page 4
	if err != nil {
		log.Printf("Error reading pages: %v", err)
	} else {
		fmt.Printf("User data (8 pages): %s\n", hex.EncodeToString(userData))
	}

	// Example 4: Write without authentication (if no protection)
	fmt.Println("\n=== Writing Data (No Authentication) ===")
	testData := []byte{0x01, 0x02, 0x03, 0x04}
	err = uc.WritePage(4, testData)
	if err != nil {
		log.Printf("Error writing page: %v", err)
	} else {
		fmt.Println("✓ Data written to page 4")
	}

	// Example 5: Authenticate with default key
	fmt.Println("\n=== Authenticating with Default Key ===")
	defaultKey := DefaultKey() // "BREAKMEIFYOUCAN!"
	fmt.Printf("Using default key: %s\n", string(defaultKey))

	err = uc.Authenticate(defaultKey)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		fmt.Println("Note: Card may be using a different key")
	} else {
		fmt.Println("✓ Authentication successful!")
		fmt.Printf("Authenticated: %v\n", uc.IsAuthenticated())
	}

	// Example 6: Read protected pages (requires authentication)
	if uc.IsAuthenticated() {
		fmt.Println("\n=== Reading Protected Pages ===")

		// Read authentication configuration
		auth0, auth1, err := uc.GetAuthConfig()
		if err != nil {
			log.Printf("Error reading auth config: %v", err)
		} else {
			fmt.Printf("AUTH0 (first protected page): 0x%02X\n", auth0)
			fmt.Printf("AUTH1 (write access): 0x%02X\n", auth1)
		}

		// Read the key (for verification)
		fmt.Println("\n=== Reading Current Key ===")
		currentKey, err := uc.ReadKey()
		if err != nil {
			log.Printf("Error reading key: %v", err)
		} else {
			fmt.Printf("Current key: %s\n", hex.EncodeToString(currentKey))
			fmt.Printf("Key (ASCII): %s\n", string(currentKey))
		}
	}

	// Example 7: Read counter
	fmt.Println("\n=== Reading Counter ===")
	counter, err := uc.GetCounter()
	if err != nil {
		log.Printf("Error reading counter: %v", err)
	} else {
		fmt.Printf("Counter value: %d\n", counter)
	}

	// Example 8: Read all user memory
	fmt.Println("\n=== Reading All User Memory ===")
	userMem, err := uc.ReadUserMemory()
	if err != nil {
		log.Printf("Error reading user memory: %v", err)
	} else {
		fmt.Printf("User memory (%d bytes):\n", len(userMem))
		// Print in 16-byte rows
		for i := 0; i < len(userMem); i += 16 {
			end := i + 16
			if end > len(userMem) {
				end = len(userMem)
			}
			fmt.Printf("  %04X: %s\n", i, hex.EncodeToString(userMem[i:end]))
		}
	}

	// Example 9: Change key (only if authenticated)
	if uc.IsAuthenticated() {
		fmt.Println("\n=== Changing Key (Example - NOT executed) ===")
		fmt.Println("To change the key, uncomment the code below:")
		fmt.Println("WARNING: Changing the key requires authentication!")

		/*
			newKey := []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			}
			err = uc.ChangeKey(newKey)
			if err != nil {
				log.Printf("Error changing key: %v", err)
			} else {
				fmt.Println("✓ Key changed successfully!")
				fmt.Println("IMPORTANT: Save your new key securely!")
			}
		*/
	}

	// Example 10: Set authentication requirements (only if authenticated)
	if uc.IsAuthenticated() {
		fmt.Println("\n=== Setting Authentication Config (Example - NOT executed) ===")
		fmt.Println("To set auth config, uncomment the code below:")

		/*
			// Require authentication from page 6 onwards
			auth0 := byte(0x06)
			// Both read and write require authentication
			auth1 := byte(0x00)

			err = uc.SetAuthConfig(auth0, auth1)
			if err != nil {
				log.Printf("Error setting auth config: %v", err)
			} else {
				fmt.Printf("✓ Auth config set: AUTH0=0x%02X, AUTH1=0x%02X\n", auth0, auth1)
			}
		*/
	}

	// Example 11: Write to user memory
	fmt.Println("\n=== Writing to User Memory ===")
	message := []byte("Hello Ultralight C!")
	// Pad to 4-byte boundary
	if len(message)%4 != 0 {
		padding := 4 - (len(message) % 4)
		message = append(message, make([]byte, padding)...)
	}

	err = uc.WriteUserMemory(4, message)
	if err != nil {
		log.Printf("Error writing user memory: %v", err)
	} else {
		fmt.Println("✓ Message written to user memory")

		// Read it back
		readBack, err := uc.ReadPages(4, len(message)/4)
		if err != nil {
			log.Printf("Error reading back: %v", err)
		} else {
			fmt.Printf("Read back: %s\n", string(readBack[:len("Hello Ultralight C!")]))
		}
	}

	fmt.Println("\n=== Examples Complete ===")
	fmt.Println("\nKey Facts about Ultralight C:")
	fmt.Println("- 192 bytes total memory (48 pages × 4 bytes)")
	fmt.Println("- Pages 0-3: UID, OTP, Lock bytes")
	fmt.Println("- Pages 4-39: User memory (144 bytes)")
	fmt.Println("- Pages 40-43: Configuration and counter")
	fmt.Println("- Pages 44-47: 3DES authentication key")
	fmt.Println("- Default key: BREAKMEIFYOUCAN!")
}

// Include minimal type definitions for example
type UltralightC struct {
	card          *scard.Card
	ctx           *scard.Context
	authenticated bool
	key           []byte
	uid           []byte
}

func NewUltralightC(card *scard.Card, ctx *scard.Context) *UltralightC {
	return &UltralightC{
		card:          card,
		ctx:           ctx,
		authenticated: false,
	}
}

func DefaultKey() []byte {
	return []byte("BREAKMEIFYOUCAN!")
}

// Note: In actual use, import the full implementation from ultralight package
// or include all methods from ultralight.go
