package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"

    gp "github.com/google/gopacket/pcap"

    "github.com/Tushar98644/PacketSentry/pkg/config"
    "github.com/Tushar98644/PacketSentry/pkg/pcap"
    "github.com/Tushar98644/PacketSentry/pkg/flow"
    "github.com/Tushar98644/PacketSentry/pkg/features"
    "github.com/Tushar98644/PacketSentry/pkg/output"
)

func main() {
    cfg := config.New()
    cfg.ParseFlags()
    if err := cfg.Validate(); err != nil {
        log.Fatalf("config error: %v", err)
    }

    if cfg.LiveCapture {
        devs, err := gp.FindAllDevs()
        if err != nil {
            log.Fatalf("could not list devices: %v", err)
        }
        fmt.Println("Available devices:")
        for _, d := range devs {
            fmt.Printf("  - %s: %s\n", d.Name, d.Description)
        }
        fmt.Printf("Using device: %s\n\n", cfg.Device)
    }

    handle, err := pcap.OpenHandle(cfg)
    if err != nil {
        log.Fatalf("could not open handle: %v", err)
    }
    defer handle.Close()

    packetCh := pcap.ReadPackets(handle)
    flows := flow.Aggregate(packetCh)

    fmt.Printf("Computed features for %d flows:\n\n", len(flows))
    
    var allFeats []features.FlowFeatures
    for i, f := range flows {
        feats := features.FromFlow(f)
        fmt.Printf("Flow %d:\n", i+1)
        fmt.Printf("  Duration: %v\n", feats.Duration)
        fmt.Printf("  Packet count: %d\n", feats.PacketCount)
        fmt.Printf("  Packet size → count=%d mean=%.2f min=%d max=%d std=%.2f\n",
            feats.PacketStats.Count,
            feats.PacketStats.Mean,
            feats.PacketStats.Min,
            feats.PacketStats.Max,
            feats.PacketStats.Std,
        )
        fmt.Printf("  IAT → count=%d mean=%v min=%v max=%v std=%v\n\n",
            feats.IATStats.Count,
            feats.IATStats.Mean,
            feats.IATStats.Min,
            feats.IATStats.Max,
            feats.IATStats.Std,
        )

        allFeats = append(allFeats, feats)
    }

    csvPath := fmt.Sprintf("%s_features.csv", cfg.FileName)
    if err := output.WriteFlowFeaturesCSV(csvPath, allFeats); err != nil {
        log.Fatalf("error writing CSV: %v", err)
    }
    fmt.Printf("Features written to %s\n", csvPath)

    model, err := ml.LoadModel("ml/parameters")
    if err != nil {
        log.Fatalf("could not load ML model: %v", err)
    }

    for i, feats := range allFeats {
        raw := []float64{
            float64(feats.Duration) / float64(time.Millisecond),
            float64(feats.PacketCount),
            feats.PacketStats.Mean,
            feats.PacketStats.Std,
        }
        prob, err := model.Predict(raw)
        if err != nil {
            log.Fatalf("predict error: %v", err)
        }
        label := "benign"
        if prob > 0.5 {
            label = "malicious"
        }
        fmt.Printf("Flow %d: probability=%.3f → %s\n", i+1, prob, label)
    }

    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()
    <-ctx.Done()
    fmt.Println("Shutting down")
}
