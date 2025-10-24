package samples

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/ebfe/scard"
	"github.com/oo-developer/acr122u/desfire"
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

	// Create DESFire instance
	df := desfire.NewDESFire(card, ctx)

	// Example 1: Get card version and UID
	fmt.Println("\n=== Getting Card Information ===")
	uid, err := df.GetUID()
	if err != nil {
		log.Printf("Error getting UID: %v", err)
	} else {
		fmt.Printf("Card UID: %s\n", hex.EncodeToString(uid))
	}

	// Example 2: List applications
	fmt.Println("\n=== Listing Applications ===")
	apps, err := df.GetApplicationIDs()
	if err != nil {
		log.Printf("Error getting applications: %v", err)
	} else {
		fmt.Printf("Found %d applications:\n", len(apps))
		for i, app := range apps {
			fmt.Printf("  %d. AID: %s\n", i+1, hex.EncodeToString(app))
		}
	}

	// Example 3: Authenticate with PICC master key
	fmt.Println("\n=== Authenticating with PICC Master Key ===")

	// Default key is all zeros (16 bytes for AES)
	defaultAESKey := make([]byte, 16)

	err = df.AuthenticateAES(0x00, defaultAESKey)
	if err != nil {
		log.Printf("AES Authentication failed: %v", err)

		// Try 3DES authentication instead
		fmt.Println("Trying 3DES authentication...")
		default3DESKey := make([]byte, 16) // 2-key 3DES
		err = df.Authenticate3DES(0x00, default3DESKey)
		if err != nil {
			log.Printf("3DES Authentication also failed: %v", err)
		} else {
			fmt.Println("✓ 3DES Authentication successful!")
		}
	} else {
		fmt.Println("✓ AES Authentication successful!")
	}

	// Example 4: Create a new application (if authenticated)
	fmt.Println("\n=== Creating New Application ===")
	newAID := []byte{0x12, 0x34, 0x56}
	keySetting := byte(0x0F) // Default settings
	numKeys := byte(0x01)    // 1 key (AES)

	err = df.CreateApplication(newAID, keySetting, numKeys)
	if err != nil {
		log.Printf("Error creating application: %v", err)
	} else {
		fmt.Printf("✓ Application created: %s\n", hex.EncodeToString(newAID))
	}

	// Example 5: Select and work with application
	fmt.Println("\n=== Working with Application ===")
	err = df.SelectApplication(newAID)
	if err != nil {
		log.Printf("Error selecting application: %v", err)
	} else {
		fmt.Printf("✓ Application selected: %s\n", hex.EncodeToString(newAID))

		// Authenticate with application master key (default: all zeros)
		err = df.AuthenticateAES(0x00, defaultAESKey)
		if err != nil {
			log.Printf("App authentication failed: %v", err)
		} else {
			fmt.Println("✓ Authenticated with application")

			// Now you can create files, read/write data, etc.
			fmt.Println("Ready to create files and manage data!")
		}
	}

	// Example 6: Read data from a file (if file exists)
	fmt.Println("\n=== Reading Data Example ===")
	fileNo := byte(0x00)
	data, err := df.ReadData(fileNo, 0, 32) // Read 32 bytes from offset 0
	if err != nil {
		log.Printf("Error reading data: %v (file may not exist)", err)
	} else {
		fmt.Printf("Data read: %s\n", hex.EncodeToString(data))
	}

	// Example 7: Write data to a file (if authenticated and file exists)
	fmt.Println("\n=== Writing Data Example ===")
	testData := []byte("Hello DESFire!")
	err = df.WriteData(fileNo, 0, testData)
	if err != nil {
		log.Printf("Error writing data: %v (file may not exist)", err)
	} else {
		fmt.Println("✓ Data written successfully")
	}

	fmt.Println("\n=== Examples Complete ===")
}

// DESFire structure (minimal definition for example)
type DESFire struct {
	card    *scard.Card
	ctx     *scard.Context
	session *SessionKey
}

type SessionKey struct {
	keyType       byte
	key           []byte
	sessionKey    []byte
	sessionKeyMAC []byte
	iv            []byte
	cmdCounter    uint16
}

// Include the key functions from desfire.go here or import as a package
// For this example, we'll need to structure this as a proper Go module

func NewDESFire(card *scard.Card, ctx *scard.Context) *DESFire {
	return &DESFire{
		card: card,
		ctx:  ctx,
	}
}

// ... (Include other methods from desfire.go or import as package)
