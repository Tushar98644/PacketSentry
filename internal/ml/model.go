package ml

import (
    "bufio"
    "fmt"
    "math"
    "os"
    "strconv"
    "strings"
)

type Model struct {
    Weights   []float64 
    Intercept float64
    Means     []float64
    Stds      []float64
}

func LoadModel(paramsDir string) (*Model, error) {
    m := &Model{}

    readFloats := func(path string) ([]float64, error) {
        f, err := os.Open(path)
        if err != nil {
            return nil, fmt.Errorf("open %s: %w", path, err)
        }
        defer f.Close()

        var vals []float64
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line == "" {
                continue
            }
            v, err := strconv.ParseFloat(line, 64)
            if err != nil {
                return nil, fmt.Errorf("parse %s: %w", path, err)
            }
            vals = append(vals, v)
        }
        return vals, scanner.Err()
    }

    var err error
    m.Weights, err = readFloats(paramsDir + "/weights.txt")
    if err != nil {
        return nil, err
    }

	intrp, err := readFloats(paramsDir + "/intercept.txt")
    if err != nil {
        return nil, err
    }
	
    if len(intrp) != 1 {
        return nil, fmt.Errorf("intercept.txt must contain exactly one value")
    }
    m.Intercept = intrp[0]

    m.Means, err = readFloats(paramsDir + "/mean.txt")
    if err != nil {
        return nil, err
    }
    m.Stds, err = readFloats(paramsDir + "/std.txt")
    if err != nil {
        return nil, err
    }

    n := len(m.Weights)
    for _, nameVal := range []struct {
        name string
        arr  []float64
    }{
        {"mean.txt", m.Means},
        {"std.txt", m.Stds},
    } {
        if len(nameVal.arr) != n {
            return nil, fmt.Errorf("%s length %d, want %d", nameVal.name, len(nameVal.arr), n)
        }
    }

    return m, nil
}

func Sigmoid(z float64) float64 {
    return 1.0 / (1.0 + math.Exp(-z))
}

func (m *Model) Predict(features []float64) (float64, error) {
    if len(features) != len(m.Weights) {
        return 0, fmt.Errorf("feature length %d, want %d", len(features), len(m.Weights))
    }

    var z float64 = m.Intercept
    for i, x := range features {
        if m.Stds[i] == 0 {
            continue
        }
        xScaled := (x - m.Means[i]) / m.Stds[i]
        z += m.Weights[i] * xScaled
    }

    return Sigmoid(z), nil
}
