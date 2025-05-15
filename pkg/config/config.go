package config

import (
    "flag"
    "fmt"
    "time"
)

type Config struct {
    LiveCapture   bool  
    FileName      string 
    MaxPackets    int
    LocalIPKnown  bool 
    LocalIP       string

    Device        string
    SnapshotLen   int32
    Promiscuous   bool
    Timeout       time.Duration
}

func New() *Config {
    return &Config{
        LiveCapture:  true,
        FileName:     "capture",
        MaxPackets:   10,
        LocalIPKnown: false,
        LocalIP:      "",
        Device:      "en0",
        SnapshotLen: 1024,
        Promiscuous: false,
        Timeout:     30 * time.Second,
    }
}

// ParseFlags binds command-line flags to the Config fields.
// Call this before using any values in cfg.
func (cfg *Config) ParseFlags() {
    flag.BoolVar(&cfg.LiveCapture, "live", cfg.LiveCapture,
        "true to capture live packets, false to read from pcap file")

    flag.StringVar(&cfg.FileName, "fname", cfg.FileName,
        "base name of the pcap file (no .pcap extension)")

    flag.IntVar(&cfg.MaxPackets, "max", cfg.MaxPackets,
        "maximum number of packets to process")

    flag.BoolVar(&cfg.LocalIPKnown, "local-known", cfg.LocalIPKnown,
        "set to true if you will supply a local IP")

    flag.StringVar(&cfg.LocalIP, "local-ip", cfg.LocalIP,
        "your local IP address (required if local-known=true)")

    flag.StringVar(&cfg.Device, "device", cfg.Device,
        "network device to capture packets from")

    // Actually parse the flags from os.Args
    flag.Parse()
}

func (cfg *Config) Validate() error {
    if !cfg.LiveCapture && cfg.FileName == "" {
        return fmt.Errorf("fname must be set when live=false")
    }
    if cfg.LocalIPKnown && cfg.LocalIP == "" {
        return fmt.Errorf("local-ip must be provided when local-known=true")
    }
    return nil
}
