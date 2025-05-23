package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "time"
    "encoding/csv"
    "path/filepath"
    "strings"
    "strconv"
    "github.com/go-echarts/go-echarts/v2/charts"
    "github.com/go-echarts/go-echarts/v2/opts"
    gp "github.com/google/gopacket/pcap"

    "github.com/Tushar98644/PacketSentry/pkg/config"
    "github.com/Tushar98644/PacketSentry/pkg/pcap"
    "github.com/Tushar98644/PacketSentry/pkg/flow"
    "github.com/Tushar98644/PacketSentry/pkg/features"
    "github.com/Tushar98644/PacketSentry/pkg/output"
    "github.com/Tushar98644/PacketSentry/internal/ml"
    "github.com/Tushar98644/PacketSentry/pkg/crypto"
)

func main() {
    cfg := config.New()
    cfg.ParseFlags()
    if err := cfg.Validate(); err != nil {
        log.Fatalf("config error: %v", err)
    }

    if cfg.DecryptMode {
        data, err := os.ReadFile(cfg.DecryptIn)
        if err != nil {
            log.Fatalf("decrypt: cannot read %s: %v", cfg.DecryptIn, err)
        }
        plain, err := crypto.Decrypt(data, cfg.DecryptKey)
        if err != nil {
            log.Fatalf("decrypt: failed: %v", err)
        }
        if err := os.WriteFile(cfg.DecryptOut, plain, 0644); err != nil {
            log.Fatalf("decrypt: write failed: %v", err)
        }
        fmt.Printf("Decrypted output written to %s\n", cfg.DecryptOut)
        return
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
        fmt.Printf("Flow %d: %s:%d -> %s:%d (%s)\n", i+1, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
        allFeats = append(allFeats, feats)
    }

    baseName := filepath.Base(cfg.FileName)
    nameOnly := strings.TrimSuffix(baseName, filepath.Ext(baseName))
    csvDir := "data/raw"

    if err := os.MkdirAll(csvDir, os.ModePerm); err != nil {
        log.Fatalf("could not create directory %s: %v", csvDir, err)
    }

    csvPath := filepath.Join(csvDir, fmt.Sprintf("%s_features.csv", nameOnly))
    if err := output.WriteFlowFeaturesCSV(csvPath, allFeats); err != nil {
        log.Fatalf("error writing CSV: %v", err)
    }
    fmt.Printf("Features written to %s\n", csvPath)

    model, err := ml.LoadModel("ml/parameters")
    if err != nil {
        log.Fatalf("could not load ML model: %v", err)
    }
    fmt.Println("Loaded model successfully")

    resultsPath := "data/results/" + baseName + ".csv"
    os.MkdirAll("data/results", os.ModePerm)
    rf, err := os.Create(resultsPath)
    if err != nil {
        log.Fatalf("failed to create results file: %v", err)
    }
    defer rf.Close()

    writer := csv.NewWriter(rf)
    defer writer.Flush()
    writer.Write([]string{
        "FlowID",
        "SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol",
        "Duration_ms", "PacketCount", "PktCount", "PktSum", "PktMean", "PktMin", "PktMax", "PktStd",
        "IATCount", "IATSum_ms", "IATMean_ms", "IATMin_ms", "IATMax_ms", "IATStd_ms",
        "Probability", "Label",
    })    

    var chartData []opts.BarData
    var xLabels []string

    for i, ftr := range allFeats {
        raw := []float64 {
            float64(ftr.Duration) / float64(time.Millisecond),
            float64(ftr.PacketCount),
            float64(ftr.PacketStats.Count),
            float64(ftr.PacketStats.Sum),
            ftr.PacketStats.Mean,
            float64(ftr.PacketStats.Min),
            float64(ftr.PacketStats.Max),
            ftr.PacketStats.Std,
            float64(ftr.IATStats.Count),
            float64(ftr.IATStats.Sum) / float64(time.Millisecond),
            float64(ftr.IATStats.Mean) / float64(time.Millisecond),
            float64(ftr.IATStats.Min) / float64(time.Millisecond),
            float64(ftr.IATStats.Max) / float64(time.Millisecond),
            float64(ftr.IATStats.Std) / float64(time.Millisecond),
        }        
        prob, err := model.Predict(raw)
        if err != nil {
            log.Fatalf("prediction error on flow %d: %v", i+1, err)
            continue
        }

        label := "benign"
        if prob > 0.5 {
            label = "malicious"
        }

        row := []string{
            strconv.Itoa(i + 1),
            ftr.SrcIP.String(),
            ftr.DstIP.String(),
            strconv.Itoa(int(ftr.SrcPort)),
            strconv.Itoa(int(ftr.DstPort)),
            ftr.Protocol,
            fmt.Sprintf("%.3f", float64(ftr.Duration)/float64(time.Millisecond)),
            strconv.Itoa(ftr.PacketCount),
            strconv.Itoa(ftr.PacketStats.Count),
            strconv.Itoa(ftr.PacketStats.Sum),
            fmt.Sprintf("%.3f", ftr.PacketStats.Mean),
            strconv.Itoa(ftr.PacketStats.Min),
            strconv.Itoa(ftr.PacketStats.Max),
            fmt.Sprintf("%.3f", ftr.PacketStats.Std),
        
            strconv.Itoa(ftr.IATStats.Count),
            fmt.Sprintf("%.3f", float64(ftr.IATStats.Sum)/float64(time.Millisecond)),
            fmt.Sprintf("%.3f", float64(ftr.IATStats.Mean)/float64(time.Millisecond)),
            fmt.Sprintf("%.3f", float64(ftr.IATStats.Min)/float64(time.Millisecond)),
            fmt.Sprintf("%.3f", float64(ftr.IATStats.Max)/float64(time.Millisecond)),
            fmt.Sprintf("%.3f", float64(ftr.IATStats.Std)/float64(time.Millisecond)),
        
            fmt.Sprintf("%.3f", prob),
            label,
        }
        
        if err := writer.Write(row); err != nil {
            log.Printf("error writing CSV row for flow %d: %v", i+1, err)
        } else {
            writer.Flush() 
        }
        
        chartData = append(chartData, opts.BarData{Value: prob})
        xLabels = append(xLabels, "Flow "+strconv.Itoa(i+1))
    }
    fmt.Printf("Successfully wrote %d flows to %s\n", len(allFeats), resultsPath)
    fmt.Println("Results written to " + resultsPath)

    if cfg.EncryptKey != "" {
        pt, err := os.ReadFile(resultsPath)
        if err != nil {
            log.Fatalf("encrypt: cannot read %s: %v", resultsPath, err)
        }
        ct, err := crypto.Encrypt(pt, cfg.EncryptKey)
        if err != nil {
            log.Fatalf("encrypt: failed: %v", err)
        }
        encPath := resultsPath + ".enc"
        if err := os.WriteFile(encPath, ct, 0644); err != nil {
            log.Fatalf("encrypt: write failed: %v", err)
        }
        os.Remove(resultsPath)
        fmt.Printf("Encrypted output written to %s\n", encPath)
    }    

    // Generate chart
    bar := charts.NewBar()
    bar.SetGlobalOptions(
        charts.WithTitleOpts(opts.Title{
            Title: "Flow Probability Chart",
        }),
        charts.WithYAxisOpts(opts.YAxis{Name: "Probability"}),
        charts.WithXAxisOpts(opts.XAxis{Name: "Flow ID"}),
    )

    bar.SetXAxis(xLabels).
        AddSeries("Malicious Probability", chartData)

    chartFile, err := os.Create("data/results/" + baseName + "_chart.html")
    if err != nil {
        log.Fatalf("could not create chart file: %v", err)
    }
    defer chartFile.Close()

    if err := bar.Render(chartFile); err != nil {
        log.Fatalf("chart rendering failed: %v", err)
    }
    fmt.Printf("Chart written to %s\n", "data/results/" + baseName + "_chart.html")
    
    fmt.Println("Press Ctrl+C to exit")

    // Wait for interrupt signal
    ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
    defer stop()
    <-ctx.Done()
    fmt.Println("Shutting down")
}
