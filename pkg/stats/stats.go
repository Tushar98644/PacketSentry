package stats

import (
    "math"
    "time"
)

type IntStats struct {
    Count int   
    Sum   int  
    Mean  float64
    Min   int
    Max   int 
    Std   float64
}

type DurationStats struct {
    Count int           
    Sum   time.Duration 
    Mean  time.Duration 
    Min   time.Duration 
    Max   time.Duration
    Std   time.Duration
}

func ComputeIntStats(xs []int) IntStats {
    s := IntStats{Count: len(xs)}
    if s.Count == 0 {
        return s
    }

    s.Min, s.Max = xs[0], xs[0]

    var sumSquares float64
    for _, x := range xs {
        s.Sum += x
        if x < s.Min {
            s.Min = x
        }
        if x > s.Max {
            s.Max = x
        }
    }
    s.Mean = float64(s.Sum) / float64(s.Count)

    for _, x := range xs {
        diff := float64(x) - s.Mean
        sumSquares += diff * diff
    }
    variance := sumSquares / float64(s.Count)
    s.Std = math.Sqrt(variance)

    return s
}

func ComputeDurationStats(ds []time.Duration) DurationStats {
    s := DurationStats{Count: len(ds)}
    if s.Count == 0 {
        return s
    }

    s.Min, s.Max = ds[0], ds[0]
    var sumSquares float64
    for _, d := range ds {
        s.Sum += d
        if d < s.Min {
            s.Min = d
        }
        if d > s.Max {
            s.Max = d
        }
    }

    meanNano := int64(s.Sum) / int64(s.Count)
    s.Mean = time.Duration(meanNano)

    for _, d := range ds {
        diff := float64(d - s.Mean)
        sumSquares += diff * diff
    }
    variance := sumSquares / float64(s.Count)
    s.Std = time.Duration(math.Sqrt(variance))

    return s
}