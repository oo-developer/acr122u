package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gousb"
)

const (
	vid = 0x072F
	pid = 0x2200

	epBulkOut = 0x01
	epBulkIn  = 0x81
	timeout   = 5000 * time.Millisecond
)

func main() {
	fmt.Println("acr122u")

	ctx := gousb.NewContext()
	defer ctx.Close()

	// Open ACR122U by VID/PID
	dev, err := ctx.OpenDeviceWithVIDPID(vid, pid)
	if err != nil {
		log.Fatalf("No ACR122U found: %v", err)
	}
	defer dev.Close()
}
