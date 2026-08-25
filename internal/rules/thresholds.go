package rules

import "math"

// DeviationRatio exposes the normalized distance from a configured threshold.
func DeviationRatio(observed, threshold float64) float64 {
	if threshold == 0 || math.IsNaN(observed) || math.IsNaN(threshold) {
		return math.Inf(1)
	}
	return math.Abs(observed-threshold) / math.Abs(threshold)
}
