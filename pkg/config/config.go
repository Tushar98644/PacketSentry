package config

import (
    "flag"
    "fmt"
)

type Config struct {
    LiveCapture   bool  
    FileName      string 
    MaxPackets    int
    LocalIPKnown  bool 
    LocalIP       string
}

func New() *Config {
    return &Config{
        LiveCapture:  false,
        FileName:     "capture",
        MaxPackets:   1000,
        LocalIPKnown: false,
        LocalIP:      "",
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
