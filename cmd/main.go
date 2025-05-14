package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"

    "github.com/Tushar98644/PacketSentry/pkg/config"
	"github.com/Tushar98644/PacketSentry/pkg/pcap"
)

func main() {
    cfg := config.New()
    cfg.ParseFlags()

    if err := cfg.Validate(); err != nil {
        log.Fatalf("config error: %v", err)
    }

    fmt.Printf("Configuration:\n")
    fmt.Printf("  live capture  = %v\n", cfg.LiveCapture)
    fmt.Printf("  pcap filename = %s.pcap\n", cfg.FileName)
    fmt.Printf("  max packets   = %d\n", cfg.MaxPackets)
    fmt.Printf("  local-known   = %v\n", cfg.LocalIPKnown)
    fmt.Printf("  local-ip      = %q\n", cfg.LocalIP)

	handle, err := pcap.OpenHandle(cfg)
    if err != nil {
        log.Fatalf("could not open pcap handle: %v", err)
    }
    defer handle.Close()

    packetCh := pcap.ReadPackets(handle)
	log.Println("Reading packets...",packetCh)

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()

	<-ctx.Done()
    fmt.Println("Shutting down gracefully")
}
