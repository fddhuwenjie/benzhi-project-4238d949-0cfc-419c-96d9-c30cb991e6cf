package rules

import (
	casepkg "envresponse/internal/case"
	"fmt"
	"math"
	"time"
)

type DriftResult struct {
	Level      string
	Minutes    int
	Trusted    bool
	Conclusion string
}

type ReliabilityResult struct {
	Score      int      `json:"score"`
	Window     string   `json:"window"`
	Penalties  []string `json:"penalties"`
	Conclusion string   `json:"conclusion"`
}

// ScoreSource uses a neutral baseline and applies bounded, explainable penalties.
func ScoreSource(events []*casepkg.EnvironmentIncident, now time.Time, window time.Duration) ReliabilityResult {
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	score := 100
	penalties := []string{}
	used := 0
	for _, e := range events {
		if now.Sub(e.ObservedAt) > window {
			continue
		}
		used++
		if e.DriftLevel == "severe" {
			score -= 20
			penalties = append(penalties, "严重时间漂移-20")
		}
		for _, h := range e.ValidationHits {
			if len(h) > 4 && h[:4] == "复核失败" {
				score -= 15
				penalties = append(penalties, "复核失败-15")
				break
			}
		}
	}
	if used > 1 {
		d := (used - 1) * 5
		score -= d
		penalties = append(penalties, fmt.Sprintf("重复命中-%d", d))
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	conclusion := "来源可靠"
	if score < 60 {
		conclusion = "来源待核验"
	}
	return ReliabilityResult{Score: score, Window: window.String(), Penalties: penalties, Conclusion: conclusion}
}

type CumulativeResult struct {
	Deviation   float64             `json:"cumulative_deviation"`
	Count       int                 `json:"cumulative_count"`
	IDs         []string            `json:"contributing_incident_ids"`
	Level       casepkg.ImpactLevel `json:"level"`
	Threshold   string              `json:"escalation_threshold"`
	Explanation string              `json:"explanation"`
}

func AssessCumulative(current *casepkg.EnvironmentIncident, history []*casepkg.EnvironmentIncident, now time.Time, window time.Duration) CumulativeResult {
	if window <= 0 {
		window = 2 * time.Hour
	}
	total := math.Abs(current.ObservedValue - current.Threshold)
	ids := []string{current.ID}
	count := 1
	for _, e := range history {
		if e.ID == current.ID || e.Status == casepkg.StatusClosed || e.VenueID != current.VenueID || e.Zone != current.Zone || e.Metric != current.Metric || now.Sub(e.ObservedAt) > window {
			continue
		}
		total += math.Abs(e.ObservedValue - e.Threshold)
		count++
		ids = append(ids, e.ID)
	}
	level := current.ImpactLevel
	threshold := "累计偏差升级边界：4次或累计偏差达到阈值"
	if count >= 4 && level == casepkg.ImpactLow {
		level = casepkg.ImpactMedium
	}
	if total >= math.Abs(current.Threshold)*1.5 {
		level = casepkg.ImpactHigh
	}
	return CumulativeResult{Deviation: total, Count: count, IDs: ids, Level: level, Threshold: threshold, Explanation: fmt.Sprintf("窗口内%d次未关闭事件，衰减前累计偏差%.3f；当前偏差%.3f", count, total-math.Abs(current.ObservedValue-current.Threshold), math.Abs(current.ObservedValue-current.Threshold))}
}

func ClassifyDrift(observed, now time.Time) DriftResult {
	m := int(math.Round(observed.Sub(now).Minutes()))
	am := m
	if am < 0 {
		am = -am
	}
	if am < 2 {
		return DriftResult{"normal", m, true, "时间接近服务时钟"}
	}
	if am < 5 {
		return DriftResult{"minor", m, true, "轻微时间漂移"}
	}
	return DriftResult{"severe", m, false, "严重时间漂移"}
}

func PhysicalRange(metric string, v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	switch metric {
	case "humidity":
		return v >= 0 && v <= 100
	case "temperature":
		return v >= -80 && v <= 80
	case "light":
		return v >= 0 && v <= 200000
	default:
		return true
	}
}

func KnownMetric(metric string) bool {
	return metric == "humidity" || metric == "temperature" || metric == "light"
}

// ValidateMetricRange ensures thresholds use the same physical unit as the metric.
func ValidateMetricRange(metric string, threshold float64) error {
	if !KnownMetric(metric) || !PhysicalRange(metric, threshold) {
		return fmt.Errorf("threshold与%s量纲范围不一致", metric)
	}
	return nil
}

type Assessment struct {
	Level                 casepkg.ImpactLevel `json:"level"`
	Deviation             float64             `json:"deviation"`
	ThresholdHit          string              `json:"threshold_hit"`
	SensitivityAdjustment string              `json:"sensitivity_adjustment"`
	Explanation           string              `json:"explanation"`
}

func validSensitivity(s string) bool { return s == "" || s == "normal" || s == "high" }
func Assess(metric string, observed, threshold float64, sensitivity string) (Assessment, error) {
	if !KnownMetric(metric) {
		return Assessment{}, fmt.Errorf("metric不受支持")
	}
	if threshold == 0 || math.IsNaN(observed) || math.IsInf(observed, 0) || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return Assessment{}, fmt.Errorf("threshold、observed_value必须为有限非零数")
	}
	if sensitivity == "" {
		sensitivity = "normal"
	}
	if !PhysicalRange(metric, observed) || !PhysicalRange(metric, threshold) {
		return Assessment{}, fmt.Errorf("threshold与metric物理范围不匹配")
	}
	if !validSensitivity(sensitivity) {
		return Assessment{}, fmt.Errorf("sensitivity不受支持")
	}
	d := DeviationRatio(observed, threshold)
	level := casepkg.ImpactLow
	hit := "低于25%"
	if d >= .5 {
		level = casepkg.ImpactHigh
		hit = "达到50%边界"
	} else if d >= .25 {
		level = casepkg.ImpactMedium
		hit = "达到25%边界"
	}
	adj := "无调整"
	if sensitivity == "high" {
		if level == casepkg.ImpactLow {
			level = casepkg.ImpactMedium
		}
		adj = "high敏感度提升最低等级并采用更严格容差"
	}
	return Assessment{level, d, hit, adj, fmt.Sprintf("%s绝对偏差%.1f%%，命中%s，%s", metric, d*100, hit, adj)}, nil
}

type VerificationResult struct {
	Passed          bool    `json:"passed"`
	Criteria        string  `json:"criteria"`
	FirstOutOfRange *int    `json:"first_out_of_range,omitempty"`
	Min             float64 `json:"min_sample"`
	Max             float64 `json:"max_sample"`
}

func VerifyDetailed(metric string, samples []float64, threshold float64, sensitivity string, start, end time.Time) (VerificationResult, error) {
	if len(samples) < 3 {
		return VerificationResult{}, fmt.Errorf("samples至少需要3个")
	}
	if threshold == 0 || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
		return VerificationResult{}, fmt.Errorf("threshold必须为有限非零数")
	}
	if !validSensitivity(sensitivity) {
		return VerificationResult{}, fmt.Errorf("sensitivity不受支持")
	}
	for n, v := range samples {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return VerificationResult{}, fmt.Errorf("samples[%d]必须为有限数", n)
		}
		if !PhysicalRange(metric, v) {
			return VerificationResult{}, fmt.Errorf("samples[%d]超出物理范围", n)
		}
	}
	if !start.IsZero() && !end.IsZero() && (end.Before(start) || end.Sub(start) > 24*time.Hour) {
		return VerificationResult{}, fmt.Errorf("复核窗口无效")
	}
	if !start.IsZero() && !end.IsZero() {
		if len(samples) > 1 {
			step := end.Sub(start) / time.Duration(len(samples)-1)
			if step <= 0 || step > 24*time.Hour {
				return VerificationResult{}, fmt.Errorf("复核窗口样本间隔无效")
			}
		}
	}
	min, max := samples[0], samples[0]
	for _, v := range samples[1:] {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	tol := math.Abs(threshold) * .05
	if sensitivity == "high" {
		tol = math.Abs(threshold) * .03
	}
	out := (*int)(nil)
	for n, v := range samples {
		if math.Abs(v-threshold) > tol {
			x := n
			out = &x
			break
		}
	}
	criteria := fmt.Sprintf("%s指标连续%d个样本，恢复容差±%.3f", metric, len(samples), tol)
	if out != nil {
		criteria = fmt.Sprintf("%s，首个越界样本索引%d", criteria, *out)
	}
	return VerificationResult{out == nil, criteria, out, min, max}, nil
}
func Verify(samples []float64, threshold float64, sensitivity string) (bool, string) {
	r, e := VerifyDetailed("metric", samples, threshold, sensitivity, time.Time{}, time.Time{})
	if e != nil {
		return false, e.Error()
	}
	return r.Passed, r.Criteria
}
