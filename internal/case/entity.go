package casepkg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type IncidentStatus string

const (
	StatusNew        IncidentStatus = "new"
	StatusAssessed   IncidentStatus = "assessed"
	StatusInProgress IncidentStatus = "in_progress"
	StatusVerifying  IncidentStatus = "verifying"
	StatusClosed     IncidentStatus = "closed"
	StatusReopened   IncidentStatus = "reopened"
)

type ImpactLevel string

const (
	ImpactLow    ImpactLevel = "low"
	ImpactMedium ImpactLevel = "medium"
	ImpactHigh   ImpactLevel = "high"
)

type EnvironmentIncident struct {
	ID                        string                   `json:"id"`
	VenueID                   string                   `json:"venue_id"`
	Zone                      string                   `json:"zone"`
	Metric                    string                   `json:"metric"`
	ObservedValue             float64                  `json:"observed_value"`
	Threshold                 float64                  `json:"threshold"`
	ObservedAt                time.Time                `json:"observed_at"`
	Source                    string                   `json:"source"`
	Sensitivity               string                   `json:"sensitivity"`
	ImpactLevel               ImpactLevel              `json:"impact_level"`
	Status                    IncidentStatus           `json:"status"`
	Revision                  int                      `json:"revision"`
	CreatedBy                 string                   `json:"created_by"`
	Tasks                     map[string]*ResponseTask `json:"tasks"`
	Verifications             []VerificationRecord     `json:"verifications"`
	Timeline                  []TimelineEvent          `json:"timeline"`
	Audit                     *AuditSummary            `json:"audit,omitempty"`
	Assessment                AssessmentDetail         `json:"assessment"`
	Fingerprint               string                   `json:"fingerprint,omitempty"`
	ValidationHits            []string                 `json:"validation_hits,omitempty"`
	DriftLevel                string                   `json:"drift_level,omitempty"`
	DriftMinutes              int                      `json:"drift_minutes,omitempty"`
	SourceTrusted             bool                     `json:"source_trusted"`
	SourceValidation          string                   `json:"source_validation,omitempty"`
	RuleVersion               string                   `json:"rule_version,omitempty"`
	AssessmentHistory         []AssessmentSnapshot     `json:"assessment_history,omitempty"`
	FailureCount              int                      `json:"failure_count,omitempty"`
	SourceReliability         int                      `json:"source_reliability"`
	SourceScoreWindow         string                   `json:"source_score_window,omitempty"`
	SourceReviewConclusion    string                   `json:"source_review_conclusion,omitempty"`
	SourcePendingVerification bool                     `json:"source_pending_verification,omitempty"`
	SourcePenaltyDetails      []string                 `json:"source_penalty_details,omitempty"`
}
type AssessmentDetail struct {
	Level                   ImpactLevel `json:"level"`
	Deviation               float64     `json:"deviation"`
	ThresholdHit            string      `json:"threshold_hit"`
	SensitivityAdjustment   string      `json:"sensitivity_adjustment"`
	Explanation             string      `json:"explanation"`
	CumulativeDeviation     float64     `json:"cumulative_deviation,omitempty"`
	CumulativeCount         int         `json:"cumulative_count,omitempty"`
	ContributingIncidentIDs []string    `json:"contributing_incident_ids,omitempty"`
	EscalationThreshold     string      `json:"escalation_threshold,omitempty"`
	CumulativeFallback      string      `json:"cumulative_fallback,omitempty"`
}
type AssessmentSnapshot struct {
	Version        string      `json:"version"`
	Sensitivity    string      `json:"sensitivity,omitempty"`
	ObservedValue  float64     `json:"observed_value"`
	Threshold      float64     `json:"threshold"`
	Level          ImpactLevel `json:"level"`
	Deviation      float64     `json:"deviation"`
	ThresholdHit   string      `json:"threshold_hit"`
	Explanation    string      `json:"explanation"`
	RecalculatedBy string      `json:"recalculated_by,omitempty"`
	At             time.Time   `json:"at"`
}
type ResponseTask struct {
	ID                  string             `json:"id"`
	IncidentID          string             `json:"incident_id"`
	Assignee            string             `json:"assignee"`
	DueAt               time.Time          `json:"due_at"`
	Instruction         string             `json:"instruction"`
	Status              string             `json:"status"`
	Measurements        map[string]float64 `json:"measurements,omitempty"`
	EvidenceNote        string             `json:"evidence_note,omitempty"`
	CompletedAt         *time.Time         `json:"completed_at,omitempty"`
	CompletedBy         string             `json:"completed_by,omitempty"`
	Revision            int                `json:"revision"`
	ClaimedBy           string             `json:"claimed_by,omitempty"`
	ClaimedAt           *time.Time         `json:"claimed_at,omitempty"`
	NeedsFollowup       bool               `json:"needs_followup,omitempty"`
	FollowupHint        string             `json:"followup_hint,omitempty"`
	LastAdjustment      string             `json:"last_adjustment,omitempty"`
	ReminderLevel       string             `json:"reminder_level,omitempty"`
	SupervisorRequired  bool               `json:"supervisor_required,omitempty"`
	OverdueNotified     bool               `json:"overdue_notified,omitempty"`
	AdjustmentHistory   []string           `json:"adjustment_history,omitempty"`
	AdjustmentActors    []string           `json:"adjustment_actors,omitempty"`
	EvidenceFingerprint string             `json:"evidence_fingerprint,omitempty"`
	FollowupTaskID      string             `json:"followup_task_id,omitempty"`
	SLAHit              bool               `json:"sla_hit,omitempty"`
	HandlingMinutes     float64            `json:"handling_minutes,omitempty"`
	OverdueMinutes      int                `json:"overdue_minutes,omitempty"`
}
type VerificationRecord struct {
	ID                  string      `json:"id"`
	IncidentID          string      `json:"incident_id"`
	WindowStart         time.Time   `json:"window_start"`
	WindowEnd           time.Time   `json:"window_end"`
	Samples             []float64   `json:"samples"`
	SampleTimes         []time.Time `json:"sample_times,omitempty"`
	Criteria            string      `json:"criteria"`
	Passed              bool        `json:"passed"`
	Reviewer            string      `json:"reviewer"`
	ReviewedAt          time.Time   `json:"reviewed_at"`
	Note                string      `json:"note"`
	BaselineDeviation   float64     `json:"baseline_deviation,omitempty"`
	MaxVariation        float64     `json:"max_variation,omitempty"`
	NeedsExtendedWindow bool        `json:"needs_extended_window,omitempty"`
	FirstOutOfRange     *int        `json:"first_out_of_range,omitempty"`
	FailureReason       string      `json:"failure_reason,omitempty"`
	Trend               string      `json:"trend,omitempty"`
	Fingerprint         string      `json:"fingerprint,omitempty"`
}
type AuditSummary struct {
	IncidentID       string          `json:"incident_id"`
	ClosedAt         time.Time       `json:"closed_at"`
	Decision         string          `json:"decision"`
	TimelineHash     string          `json:"timeline_hash"`
	ActorChain       []string        `json:"actor_chain"`
	OpenTaskCount    int             `json:"open_task_count"`
	SummaryText      string          `json:"summary_text"`
	TimelineSnapshot []TimelineEvent `json:"timeline_snapshot,omitempty"`
}
type TimelineEvent struct {
	At     time.Time `json:"at"`
	Type   string    `json:"type"`
	Actor  string    `json:"actor"`
	Detail string    `json:"detail"`
}

func (i *EnvironmentIncident) AddEvent(typ, actor, detail string) {
	i.Timeline = append(i.Timeline, TimelineEvent{time.Now().UTC(), typ, actor, detail})
	i.Revision++
}
func (i *EnvironmentIncident) OpenTasks() int {
	n := 0
	for _, t := range i.Tasks {
		if t.Status != "completed" {
			n++
		}
	}
	return n
}
func (i *EnvironmentIncident) TimelineHash() string {
	ev := append([]TimelineEvent(nil), i.Timeline...)
	sort.Slice(ev, func(a, b int) bool { return ev[a].At.Before(ev[b].At) })
	var b strings.Builder
	for _, e := range ev {
		fmt.Fprintf(&b, "%s|%s|%s|%s;", e.At.Format(time.RFC3339Nano), e.Type, e.Actor, e.Detail)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}
