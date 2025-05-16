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

    EncryptKey  string `flag:"encrypt-key" help:"Passphrase to encrypt output files (optional)"`
    DecryptKey  string `flag:"decrypt-key" help:"Passphrase to decrypt an encrypted results file"`
    DecryptMode bool   `flag:"decrypt"     help:"Run in decryption mode (reads .enc, writes plaintext)"`
    DecryptIn   string `flag:"in"          help:"Input .enc file path (required in decrypt mode)"`
    DecryptOut  string `flag:"out"         help:"Output plaintext file path (required in decrypt mode)"`
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

    flag.StringVar(&cfg.EncryptKey, "encrypt-key", "", "Passphrase to encrypt output files (optional)")
    flag.StringVar(&cfg.DecryptKey, "decrypt-key", "", "Passphrase to decrypt an encrypted results file")
    flag.BoolVar(&cfg.DecryptMode, "decrypt", false, "Run in decryption mode (reads .enc, writes plaintext)")
    flag.StringVar(&cfg.DecryptIn, "in", "", "Input .enc file path (required in decrypt mode)")
    flag.StringVar(&cfg.DecryptOut, "out", "", "Output plaintext file path (required in decrypt mode)")

    flag.Parse()
}

func (cfg *Config) Validate() error {
    if !cfg.LiveCapture && cfg.FileName == "" {
        return fmt.Errorf("fname must be set when live=false")
    }
    if cfg.LocalIPKnown && cfg.LocalIP == "" {
        return fmt.Errorf("local-ip must be provided when local-known=true")
    }
    if cfg.DecryptMode {
        if cfg.DecryptKey == "" || cfg.DecryptIn == "" || cfg.DecryptOut == "" {
            return fmt.Errorf("decrypt mode requires --decrypt-key, --in, and --out")
        }
    }
    if cfg.EncryptKey != "" && cfg.DecryptMode {
        return fmt.Errorf("--encrypt-key cannot be used with --decrypt")
    }
    return nil
}
