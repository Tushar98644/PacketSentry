package output

import (
    "encoding/csv"
    "fmt"
    "os"
    "strconv"
    "time"

    "github.com/Tushar98644/PacketSentry/pkg/features"
)


func WriteFlowFeaturesCSV(path string, feats []features.FlowFeatures) error {
    f, err := os.Create(path)
    if err != nil {
        return fmt.Errorf("could not create CSV file: %w", err)
    }
    defer f.Close()

    w := csv.NewWriter(f)
    defer w.Flush()

    header := []string{
        "Duration_ms",
        "PacketCount",
        "PktCount",
        "PktSum",
        "PktMean",
        "PktMin",
        "PktMax",
        "PktStd",
        "IATCount",
        "IATSum_ms",
        "IATMean_ms",
        "IATMin_ms",
        "IATMax_ms",
        "IATStd_ms",
    }
    if err := w.Write(header); err != nil {
        return fmt.Errorf("could not write header: %w", err)
    }

    for _, ftr := range feats {
        durMs := float64(ftr.Duration) / float64(time.Millisecond)
        iatSumMs := float64(ftr.IATStats.Sum) / float64(time.Millisecond)
        iatMeanMs := float64(ftr.IATStats.Mean) / float64(time.Millisecond)
        iatMinMs := float64(ftr.IATStats.Min) / float64(time.Millisecond)
        iatMaxMs := float64(ftr.IATStats.Max) / float64(time.Millisecond)
        iatStdMs := float64(ftr.IATStats.Std) / float64(time.Millisecond)

        row := []string{
            fmt.Sprintf("%.3f", durMs),
            strconv.Itoa(ftr.PacketCount),
            strconv.Itoa(ftr.PacketStats.Count),
            strconv.Itoa(ftr.PacketStats.Sum),
            fmt.Sprintf("%.3f", ftr.PacketStats.Mean),
            strconv.Itoa(ftr.PacketStats.Min),
            strconv.Itoa(ftr.PacketStats.Max),
            fmt.Sprintf("%.3f", ftr.PacketStats.Std),
            strconv.Itoa(ftr.IATStats.Count),
            fmt.Sprintf("%.3f", iatSumMs),
            fmt.Sprintf("%.3f", iatMeanMs),
            fmt.Sprintf("%.3f", iatMinMs),
            fmt.Sprintf("%.3f", iatMaxMs),
            fmt.Sprintf("%.3f", iatStdMs),
        }
        if err := w.Write(row); err != nil {
            return fmt.Errorf("could not write row: %w", err)
        }
    }

    return nil
}