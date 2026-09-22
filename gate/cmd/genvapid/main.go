package main

import (
	"fmt"
	"os"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/zzzLobster/stepik-discuss/gate/config"
)

func main() {
	priv, pub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		fmt.Fprintln(os.Stderr, "GenerateVAPIDKeys:", err)
		os.Exit(1)
	}
	fmt.Printf("VAPID_PUBLIC_KEY=%s\n", pub)
	fmt.Printf("VAPID_PRIVATE_KEY=%s\n", priv)
	fmt.Printf("VAPID_FP8=%s\n", config.VapidFP8(pub))
}
