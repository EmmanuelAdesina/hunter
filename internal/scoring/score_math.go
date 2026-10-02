package scoring

import "math"

// log is isolated so that the scoring file's arithmetic stays readable.
func log(x float64) float64 { return math.Log(x) }
