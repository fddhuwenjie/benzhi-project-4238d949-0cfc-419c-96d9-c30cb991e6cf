package httpapi

import (
	"encoding/json"
	casepkg "envresponse/internal/case"
	"envresponse/internal/rules"
	"envresponse/internal/workflow"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Server struct {
	flow *workflow.Service
	mux  *http.ServeMux
}

func New(f *workflow.Service) *Server {
	s := &Server{flow: f, mux: http.NewServeMux()}
	s.mux.HandleFunc("/v1/incidents", s.incidents)
	s.mux.HandleFunc("/v1/incidents/", s.sub)
	return s
}
func (s *Server) Handler() http.Handler { return s.mux }
func write(w http.ResponseWriter, c int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(r *http.Request, v any) error {
	if r.Method != "GET" && RequestID(r) == "" {
		return errors.New("缺少 Idempotency-Key")
	}
	return json.NewDecoder(r.Body).Decode(v)
}

type createReq struct {
	VenueID                  string    `json:"venue_id"`
	Zone                     string    `json:"zone"`
	Metric                   string    `json:"metric"`
	ObservedValue            float64   `json:"observed_value"`
	Threshold                float64   `json:"threshold"`
	ObservedAt               time.Time `json:"observed_at"`
	Source                   string    `json:"source"`
	Sensitivity              string    `json:"sensitivity"`
	CreatedBy                string    `json:"created_by"`
	Assignee                 string    `json:"assignee"`
	DueMinutes               int       `json:"due_minutes"`
	RuleVersion              string    `json:"rule_version"`
	SensitivityRevision      string    `json:"sensitivity_revision"`
	RecalculatedBy           string    `json:"recalculated_by"`
	SourceReviewThreshold    int       `json:"source_review_threshold"`
	SourceScoreWindowMinutes int       `json:"source_score_window_minutes"`
	CumulativeWindowMinutes  int       `json:"cumulative_window_minutes"`
}

func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		q := r.URL.Query()
		f := workflow.ListFilter{VenueID: q.Get("venue_id"), Zone: q.Get("zone"), Status: casepkg.IncidentStatus(q.Get("status")), Impact: casepkg.ImpactLevel(q.Get("impact_level")), Assignee: q.Get("assignee"), TaskStatus: q.Get("task_status"), Page: 1, PageSize: 20}
		if q.Get("overdue_only") != "" {
			if q.Get("overdue_only") != "true" && q.Get("overdue_only") != "false" {
				write(w, 400, map[string]string{"error": "overdue_only必须为布尔值"})
				return
			}
			f.OverdueOnly = q.Get("overdue_only") == "true"
		}
		if f.TaskStatus != "" {
			ok := map[string]bool{"open": true, "in_progress": true, "overdue": true, "completed": true}
			if !ok[f.TaskStatus] {
				write(w, 400, map[string]string{"error": "task_status无效"})
				return
			}
		}
		var e error
		if q.Get("page") != "" {
			f.Page, e = strconv.Atoi(q.Get("page"))
			if e != nil || f.Page < 1 {
				write(w, 400, map[string]string{"error": "page无效"})
				return
			}
		}
		if q.Get("page_size") != "" {
			f.PageSize, e = strconv.Atoi(q.Get("page_size"))
			if e != nil || f.PageSize < 1 || f.PageSize > 100 {
				write(w, 400, map[string]string{"error": "page_size无效"})
				return
			}
		}
		if q.Get("from") != "" {
			f.From, e = time.Parse(time.RFC3339, q.Get("from"))
			if e != nil {
				write(w, 400, map[string]string{"error": "from无效"})
				return
			}
		}
		if q.Get("to") != "" {
			f.To, e = time.Parse(time.RFC3339, q.Get("to"))
			if e != nil {
				write(w, 400, map[string]string{"error": "to无效"})
				return
			}
		}
		if !f.From.IsZero() && !f.To.IsZero() && f.From.After(f.To) {
			write(w, 400, map[string]string{"error": "时间范围无效"})
			return
		}
		allowed := map[casepkg.IncidentStatus]bool{"": true, casepkg.StatusNew: true, casepkg.StatusAssessed: true, casepkg.StatusInProgress: true, casepkg.StatusVerifying: true, casepkg.StatusClosed: true, casepkg.StatusReopened: true}
		if !allowed[f.Status] {
			write(w, 400, map[string]string{"error": "status无效"})
			return
		}
		if q.Get("sort") != "" && q.Get("sort") != "impact" && q.Get("sort") != "deviation" && q.Get("sort") != "observed_at" {
			write(w, 400, map[string]string{"error": "sort不受支持"})
			return
		}
		f.Sort = q.Get("sort")
		list, total, open, high, counts, groups, _ := s.flow.ListDetailed(f)
		slaHit, overdue, handled := 0, 0, 0.0
		for _, in := range list {
			for _, t := range in.Tasks {
				if t.CompletedAt == nil && time.Now().UTC().After(t.DueAt) {
					overdue++
					continue
				}
				if t.CompletedAt == nil {
					continue
				}
				if t.SLAHit {
					slaHit++
				}
				if t.OverdueMinutes > 0 {
					overdue++
				}
				handled += t.HandlingMinutes
			}
		}
		write(w, 200, map[string]any{"incidents": list, "total": total, "open_count": open, "high_impact_count": high, "status_counts": counts, "risk_groups": groups, "sla_hit_count": slaHit, "overdue_task_count": overdue, "handling_minutes_total": handled, "page": f.Page, "page_size": f.PageSize, "high_risk_ratio": func() float64 {
			if total == 0 {
				return 0
			}
			return float64(high) / float64(total)
		}()})
		return
	}
	if r.Method != "POST" {
		write(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	var q createReq
	if e := decode(r, &q); e != nil {
		write(w, 400, map[string]string{"error": e.Error()})
		return
	}
	key := RequestID(r)
	if q.SensitivityRevision != "" && q.SensitivityRevision != "normal" && q.SensitivityRevision != "high" {
		write(w, 400, map[string]string{"error": "sensitivity_revision不受支持"})
		return
	}
	_, _, replayed := s.flow.RepoIdempotency(key)
	i, a, e := s.flow.CreateIncident(workflow.CreateInput{VenueID: q.VenueID, Zone: q.Zone, Metric: q.Metric, ObservedValue: q.ObservedValue, Threshold: q.Threshold, ObservedAt: q.ObservedAt, Source: q.Source, Sensitivity: q.Sensitivity, CreatedBy: q.CreatedBy, Assignee: q.Assignee, DueMinutes: q.DueMinutes, RuleVersion: q.RuleVersion, IdempotencyKey: key, SourceReviewThreshold: q.SourceReviewThreshold, SourceScoreWindow: time.Duration(q.SourceScoreWindowMinutes) * time.Minute, CumulativeWindow: time.Duration(q.CumulativeWindowMinutes) * time.Minute})
	if e != nil {
		if errors.Is(e, casepkg.ErrConflict) {
			if i != nil {
				write(w, 200, map[string]any{"incident": i, "assessment": a, "deduplicated": true, "replayed": false})
			} else {
				write(w, 409, map[string]string{"error": "幂等键指纹冲突"})
			}
		} else {
			write(w, status(e), map[string]string{"error": e.Error()})
		}
		return
	}
	if q.SensitivityRevision != "" && !replayed {
		actor := q.RecalculatedBy
		if actor == "" {
			actor = q.CreatedBy
		}
		if ri, re := s.flow.Reassess(i.ID, q.SensitivityRevision, actor); re != nil {
			write(w, status(re), map[string]string{"error": re.Error()})
			return
		} else {
			i = ri
			a = rules.Assessment{Level: ri.ImpactLevel, Deviation: ri.Assessment.Deviation, ThresholdHit: ri.Assessment.ThresholdHit, SensitivityAdjustment: ri.Assessment.SensitivityAdjustment, Explanation: ri.Assessment.Explanation}
		}
	}
	code := 201
	if replayed {
		code = 200
	}
	write(w, code, map[string]any{"incident": i, "assessment": a, "replayed": replayed})
}
func (s *Server) sub(w http.ResponseWriter, r *http.Request) {
	p := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/incidents/"), "/"), "/")
	if len(p) == 0 || p[0] == "" {
		write(w, 404, nil)
		return
	}
	id := p[0]
	if r.Method == "GET" && len(p) == 1 {
		i, e := s.flow.Get(id)
		if e != nil {
			write(w, 404, map[string]string{"error": "事件不存在"})
			return
		}
		if r.URL.Query().Get("verification") == "true" {
			q := r.URL.Query()
			recs := make([]casepkg.VerificationRecord, 0, len(i.Verifications))
			var from, to time.Time
			var pe error
			if q.Get("from") != "" {
				from, pe = time.Parse(time.RFC3339, q.Get("from"))
			}
			if pe != nil {
				write(w, 400, map[string]string{"error": "from无效"})
				return
			}
			if q.Get("to") != "" {
				to, pe = time.Parse(time.RFC3339, q.Get("to"))
			}
			if pe != nil || (!from.IsZero() && !to.IsZero() && from.After(to)) {
				write(w, 400, map[string]string{"error": "时间范围无效"})
				return
			}
			if q.Get("passed") != "" && q.Get("passed") != "true" && q.Get("passed") != "false" {
				write(w, 400, map[string]string{"error": "passed必须为布尔值"})
				return
			}
			if !from.IsZero() && !to.IsZero() && to.Sub(from) > 24*time.Hour {
				write(w, 400, map[string]string{"error": "时间范围不得超过24小时"})
				return
			}
			for _, vr := range i.Verifications {
				if q.Get("reviewer") != "" && vr.Reviewer != q.Get("reviewer") {
					continue
				}
				if q.Get("passed") != "" && strconv.FormatBool(vr.Passed) != q.Get("passed") {
					continue
				}
				if !from.IsZero() && vr.ReviewedAt.Before(from) {
					continue
				}
				if !to.IsZero() && vr.ReviewedAt.After(to) {
					continue
				}
				recs = append(recs, vr)
			}
			var latest any
			if len(recs) > 0 {
				latest = recs[len(recs)-1]
			}
			passed := 0
			streak := 0
			for n := len(recs) - 1; n >= 0 && recs[n].Passed; n-- {
				streak++
			}
			min, max := 0.0, 0.0
			outlier := -1
			for n, v := range recs {
				if v.Passed {
					passed++
				}
				for j, x := range v.Samples {
					if n == 0 && j == 0 || x < min {
						min = x
					}
					if n == 0 && j == 0 || x > max {
						max = x
					}
				}
				if outlier < 0 && !v.Passed {
					outlier = n
				}
			}
			rate := 0.0
			if len(recs) > 0 {
				rate = float64(passed) / float64(len(recs))
			}
			var minv, maxv any
			if len(recs) > 0 {
				minv = min
				maxv = max
			}
			trend := ""
			if len(recs) > 0 {
				trend = recs[len(recs)-1].Trend
			}
			write(w, 200, map[string]any{"incident": i, "records": recs, "latest": latest, "pass_rate": rate, "pass_streak": streak, "min_sample": minv, "max_sample": maxv, "trend": trend, "outlier_index": func() any {
				if outlier < 0 {
					return nil
				}
				return outlier
			}(), "filtered_count": len(recs)})
			return
		}
		write(w, 200, i)
		return
	}
	if len(p) == 2 && p[1] == "audit" && r.Method == "GET" {
		q := r.URL.Query()
		page, pageSize := 1, 20
		var e error
		if q.Get("page") != "" {
			page, e = strconv.Atoi(q.Get("page"))
		}
		if e != nil || page < 1 {
			write(w, 400, map[string]string{"error": "page无效"})
			return
		}
		if q.Get("page_size") != "" {
			pageSize, e = strconv.Atoi(q.Get("page_size"))
			if e != nil || pageSize < 1 || pageSize > 100 {
				write(w, 400, map[string]string{"error": "page_size无效"})
				return
			}
		}
		a, ok, e := s.flow.Audit(id)
		if e != nil {
			write(w, 404, map[string]string{"error": "审计摘要不存在"})
			return
		}
		if !ok {
			write(w, 409, map[string]any{"error": "完整性冲突", "integrity": "conflict", "audit": a})
			return
		}
		include := r.URL.Query().Get("include_timeline") == "true"
		out := map[string]any{"audit": a, "integrity": "ok"}
		if include {
			start := (page - 1) * pageSize
			if start > len(a.TimelineSnapshot) {
				start = len(a.TimelineSnapshot)
			}
			end := start + pageSize
			if end > len(a.TimelineSnapshot) {
				end = len(a.TimelineSnapshot)
			}
			out["timeline"] = a.TimelineSnapshot[start:end]
			out["page"] = page
			out["page_size"] = pageSize
			out["has_more"] = end < len(a.TimelineSnapshot)
		}
		write(w, 200, out)
		return
	}
	if len(p) == 2 && p[1] == "verification" && r.Method == "POST" {
		var q struct {
			Reviewer    string      `json:"reviewer"`
			Samples     []float64   `json:"samples"`
			SampleTimes []time.Time `json:"sample_times"`
			Note        string      `json:"note"`
			WindowStart time.Time   `json:"window_start"`
			WindowEnd   time.Time   `json:"window_end"`
		}
		if e := decode(r, &q); e != nil {
			write(w, 400, map[string]string{"error": e.Error()})
			return
		}
		start, end := q.WindowStart, q.WindowEnd
		if start.IsZero() || end.IsZero() {
			end = time.Now().UTC()
			start = end.Add(-time.Duration(len(q.Samples)-1) * time.Minute)
		}
		i, v, e := s.flow.VerifyWindowWithTimes(id, q.Reviewer, q.Samples, q.SampleTimes, q.Note, start, end)
		if e != nil {
			write(w, status(e), map[string]string{"error": e.Error()})
			return
		}
		write(w, 200, map[string]any{"incident": i, "verification": v})
		return
	}
	if len(p) == 2 && p[1] == "reassess" && r.Method == "POST" {
		var q struct {
			Sensitivity string `json:"sensitivity"`
			Actor       string `json:"actor"`
		}
		if e := decode(r, &q); e != nil {
			write(w, 400, map[string]string{"error": e.Error()})
			return
		}
		i, replayed, e := s.flow.ReassessWithKey(id, q.Sensitivity, q.Actor, r.Header.Get("Idempotency-Key"))
		if e != nil {
			write(w, status(e), map[string]string{"error": e.Error()})
			return
		}
		write(w, 200, map[string]any{"incident": i, "replayed": replayed})
		return
	}
	if len(p) == 4 && p[1] == "tasks" && p[3] == "claim" && r.Method == "POST" {
		var q struct {
			Actor string `json:"actor"`
		}
		if e := decode(r, &q); e != nil {
			write(w, 400, map[string]string{"error": e.Error()})
			return
		}
		i, e := s.flow.ClaimTask(id, p[2], q.Actor)
		if e != nil {
			write(w, status(e), map[string]string{"error": e.Error()})
			return
		}
		write(w, 200, i)
		return
	}
	if len(p) == 4 && p[1] == "tasks" && p[3] == "complete" && r.Method == "POST" {
		var q struct {
			Action              string             `json:"action"`
			Actor               string             `json:"actor"`
			EvidenceNote        string             `json:"evidence_note"`
			Measurements        map[string]float64 `json:"measurements"`
			SupervisorConfirmed bool               `json:"supervisor_confirmed"`
		}
		if e := decode(r, &q); e != nil {
			write(w, 400, map[string]string{"error": e.Error()})
			return
		}
		if q.Action == "claim" {
			i, e := s.flow.ClaimTask(id, p[2], q.Actor)
			if e != nil {
				write(w, status(e), map[string]string{"error": e.Error()})
				return
			}
			write(w, 200, i)
			return
		}
		i, e := s.flow.CompleteTask(id, p[2], q.Actor, q.EvidenceNote, q.Measurements, q.SupervisorConfirmed)
		if e != nil {
			write(w, status(e), map[string]string{"error": e.Error()})
			return
		}
		out := map[string]any{"incident": i}
		if t := i.Tasks[p[2]]; t != nil {
			out["task"] = t
			out["reminder_level"] = t.ReminderLevel
			out["supervisor_required"] = t.SupervisorRequired
			out["sla_hit"] = t.SLAHit
			out["handling_minutes"] = t.HandlingMinutes
			out["overdue_minutes"] = t.OverdueMinutes
			out["followup_task_id"] = t.FollowupTaskID
			out["retest_deviation"] = func() float64 {
				if i.Metric != "" {
					if v, ok := t.Measurements[i.Metric]; ok {
						return v - i.Threshold
					}
				}
				return 0
			}()
		}
		write(w, 200, out)
		return
	}
	if len(p) == 4 && p[1] == "tasks" && p[3] == "adjust" && r.Method == "POST" {
		var q struct {
			Actor               string    `json:"actor"`
			Assignee            string    `json:"assignee"`
			DueAt               time.Time `json:"due_at"`
			Reason              string    `json:"reason"`
			SupervisorConfirmed bool      `json:"supervisor_confirmed"`
		}
		if e := decode(r, &q); e != nil {
			write(w, 400, map[string]string{"error": e.Error()})
			return
		}
		i, e := s.flow.AdjustTaskWithAssignee(id, p[2], q.Actor, q.Assignee, q.DueAt, q.Reason, q.SupervisorConfirmed)
		if e != nil {
			write(w, status(e), map[string]string{"error": e.Error()})
			return
		}
		write(w, 200, i)
		return
	}
	write(w, 404, map[string]string{"error": "route not found"})
}
func status(e error) int {
	if errors.Is(e, casepkg.ErrStorage) {
		return http.StatusServiceUnavailable
	}
	if errors.Is(e, casepkg.ErrNotFound) {
		return 404
	}
	if errors.Is(e, casepkg.ErrConflict) {
		return 409
	}
	return 400
}
