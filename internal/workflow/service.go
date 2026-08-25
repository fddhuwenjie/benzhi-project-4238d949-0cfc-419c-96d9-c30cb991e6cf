package workflow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	casepkg "envresponse/internal/case"
	"envresponse/internal/rules"
	"envresponse/internal/store"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Service struct {
	repo        store.Repository
	Retention   time.Duration
	DedupWindow time.Duration
	MaxReopens  int
}

func New(repo store.Repository) *Service {
	return &Service{repo: repo, Retention: 90 * 24 * time.Hour, DedupWindow: 10 * time.Minute, MaxReopens: 3}
}
func (s *Service) Get(id string) (*casepkg.EnvironmentIncident, error) { return s.repo.Get(id) }
func (s *Service) RepoIdempotency(key string) (string, string, bool)   { return s.repo.Idempotency(key) }
func newID() string                                                    { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }

type CreateInput struct {
	VenueID, Zone, Metric, Source, CreatedBy, Sensitivity, IdempotencyKey string
	ObservedValue, Threshold                                              float64
	ObservedAt                                                            time.Time
	Assignee                                                              string
	DueMinutes                                                            int
	RuleVersion                                                           string
	SourceReviewThreshold                                                 int
	SourceScoreWindow                                                     time.Duration
	CumulativeWindow                                                      time.Duration
}

var tokenRE = regexp.MustCompile(`^[\p{L}\p{N}._:/-]+$`)

func validToken(name, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s不能为空", name)
	}
	if !tokenRE.MatchString(v) {
		return fmt.Errorf("%s包含非法字符", name)
	}
	return nil
}
func fingerprint(in CreateInput) string {
	// 时间窗内同一场馆、分区、指标、来源和相同偏差只生成一个事件。
	bucket := in.ObservedAt.UTC().Unix() / 600
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%d|%.3f|%.3f", in.VenueID, in.Zone, in.Metric, in.Source, in.Sensitivity, bucket, in.ObservedValue, in.Threshold)))
	return hex.EncodeToString(h[:])
}
func (s *Service) CreateIncident(in CreateInput) (*casepkg.EnvironmentIncident, rules.Assessment, error) {
	if in.Sensitivity == "" {
		in.Sensitivity = "normal"
	}
	for _, p := range [][2]string{{"venue_id", in.VenueID}, {"zone", in.Zone}, {"metric", in.Metric}, {"source", in.Source}} {
		if e := validToken(p[0], p[1]); e != nil {
			return nil, rules.Assessment{}, e
		}
	}
	if len(in.Source) > 80 || !regexp.MustCompile(`^(sensor|gateway|manual)-[A-Za-z0-9._:/-]{1,64}$`).MatchString(in.Source) {
		return nil, rules.Assessment{}, fmt.Errorf("来源不可信：source必须使用已登记前缀sensor-、gateway-或manual-")
	}
	now := time.Now().UTC()
	if in.ObservedAt.IsZero() {
		return nil, rules.Assessment{}, fmt.Errorf("observed_at不能为空")
	}
	// 幂等重放必须复用首次登记时的漂移和来源结论，不能因稍后重放时钟变化而重新拒绝。
	fp := fingerprint(in)
	if in.IdempotencyKey != "" {
		if id, oldfp, ok := s.repo.Idempotency(in.IdempotencyKey); ok {
			if oldfp != fp {
				return nil, rules.Assessment{}, casepkg.ErrConflict
			}
			i, e := s.repo.Get(id)
			if e != nil {
				return nil, rules.Assessment{}, e
			}
			return i, rules.Assessment{Level: i.ImpactLevel, Deviation: i.Assessment.Deviation, ThresholdHit: i.Assessment.ThresholdHit, SensitivityAdjustment: i.Assessment.SensitivityAdjustment, Explanation: i.Assessment.Explanation}, nil
		}
	}
	drift := in.ObservedAt.Sub(now)
	if drift > 5*time.Minute {
		return nil, rules.Assessment{}, fmt.Errorf("observed_at不能晚于当前时间")
	}
	if in.ObservedAt.Before(now.Add(-s.Retention)) {
		return nil, rules.Assessment{}, fmt.Errorf("observed_at超出保留窗口")
	}
	dr := rules.ClassifyDrift(in.ObservedAt, now)
	if drift > 0 && dr.Level == "severe" {
		return nil, rules.Assessment{}, fmt.Errorf("observed_at未来漂移过大")
	}
	if math.IsNaN(in.ObservedValue) || math.IsInf(in.ObservedValue, 0) || math.IsNaN(in.Threshold) || math.IsInf(in.Threshold, 0) {
		return nil, rules.Assessment{}, fmt.Errorf("观测值必须为有限数")
	}
	if !rules.PhysicalRange(in.Metric, in.ObservedValue) {
		return nil, rules.Assessment{}, fmt.Errorf("观测值超出物理范围")
	}
	if e := rules.ValidateMetricRange(in.Metric, in.Threshold); e != nil {
		return nil, rules.Assessment{}, e
	}
	if old, e := s.repo.FindByFingerprint(fp); e == nil {
		prior := old.Revision
		old.AddEvent("dedup_hit", in.CreatedBy, "时间窗内指纹重复，复用既有事件")
		_ = s.repo.Save(old, prior)
		if in.IdempotencyKey != "" {
			_ = s.repo.BindIdempotency(in.IdempotencyKey, old.ID, fp)
		}
		return old, rules.Assessment{Level: old.ImpactLevel, Deviation: old.Assessment.Deviation, ThresholdHit: old.Assessment.ThresholdHit, SensitivityAdjustment: old.Assessment.SensitivityAdjustment, Explanation: old.Assessment.Explanation}, casepkg.ErrConflict
	}
	// 同一来源在同一时间窗内再次上报时关联既有聚合，避免重复派工。
	if all, _ := s.repo.List(); all != nil {
		for _, prior := range all {
			if prior.VenueID == in.VenueID && prior.Zone == in.Zone && prior.Metric == in.Metric && prior.Source == in.Source && absDuration(prior.ObservedAt.Sub(in.ObservedAt)) <= s.DedupWindow {
				oldRev := prior.Revision
				prior.AddEvent("dedup_hit", in.CreatedBy, "来源时间窗重复，关联原事件"+prior.ID)
				_ = s.repo.Save(prior, oldRev)
				if in.IdempotencyKey != "" {
					_ = s.repo.BindIdempotency(in.IdempotencyKey, prior.ID, fp)
				}
				return prior, rules.Assessment{Level: prior.ImpactLevel, Deviation: prior.Assessment.Deviation, ThresholdHit: prior.Assessment.ThresholdHit, SensitivityAdjustment: prior.Assessment.SensitivityAdjustment, Explanation: prior.Assessment.Explanation}, casepkg.ErrConflict
			}
		}
	}
	a, e := rules.Assess(in.Metric, in.ObservedValue, in.Threshold, in.Sensitivity)
	if e != nil {
		return nil, a, e
	}
	if in.RuleVersion == "" {
		in.RuleVersion = "v1"
	}
	id := newID()
	// 读取历史并在创建前完成来源信誉与分区累计评估，任何存储失败都拒绝登记。
	history, e := s.repo.List()
	if e != nil {
		return nil, a, fmt.Errorf("%w: 历史查询失败: %v", casepkg.ErrStorage, e)
	}
	if in.SourceScoreWindow <= 0 {
		in.SourceScoreWindow = 30 * 24 * time.Hour
	}
	relEvents := make([]*casepkg.EnvironmentIncident, 0)
	for _, old := range history {
		if old.Source == in.Source {
			relEvents = append(relEvents, old)
		}
	}
	rel := rules.ScoreSource(relEvents, now, in.SourceScoreWindow)
	if in.SourceReviewThreshold <= 0 {
		in.SourceReviewThreshold = 60
	}
	if in.CumulativeWindow <= 0 {
		in.CumulativeWindow = 2 * time.Hour
	}
	cur := &casepkg.EnvironmentIncident{ID: id, VenueID: in.VenueID, Zone: in.Zone, Metric: in.Metric, ObservedValue: in.ObservedValue, Threshold: in.Threshold, ObservedAt: in.ObservedAt, ImpactLevel: a.Level}
	cum := rules.AssessCumulative(cur, history, now, in.CumulativeWindow)
	if impactRank(cum.Level) > impactRank(a.Level) {
		a.Level = cum.Level
		a.Explanation += "; " + cum.Explanation
	}
	i := &casepkg.EnvironmentIncident{ID: id, VenueID: in.VenueID, Zone: in.Zone, Metric: in.Metric, ObservedValue: in.ObservedValue, Threshold: in.Threshold, ObservedAt: in.ObservedAt, Source: in.Source, Sensitivity: in.Sensitivity, ImpactLevel: a.Level, Status: casepkg.StatusAssessed, Revision: 1, CreatedBy: in.CreatedBy, Tasks: map[string]*casepkg.ResponseTask{}, Assessment: casepkg.AssessmentDetail{Level: a.Level, Deviation: a.Deviation, ThresholdHit: a.ThresholdHit, SensitivityAdjustment: a.SensitivityAdjustment, Explanation: a.Explanation}, Fingerprint: fp, DriftLevel: dr.Level, DriftMinutes: dr.Minutes, SourceTrusted: dr.Trusted, SourceValidation: "来源前缀校验通过", RuleVersion: in.RuleVersion}
	i.SourceReliability, i.SourceScoreWindow, i.SourceReviewConclusion, i.SourcePenaltyDetails = rel.Score, rel.Window, rel.Conclusion, rel.Penalties
	i.SourcePendingVerification = rel.Score < in.SourceReviewThreshold
	i.Assessment.CumulativeDeviation, i.Assessment.CumulativeCount, i.Assessment.ContributingIncidentIDs, i.Assessment.EscalationThreshold = cum.Deviation, cum.Count, cum.IDs, cum.Threshold
	if len(history) == 0 {
		i.Assessment.CumulativeFallback = "历史事件缺失，已降级为单次评估"
	}
	i.AssessmentHistory = []casepkg.AssessmentSnapshot{{Version: in.RuleVersion, Sensitivity: in.Sensitivity, ObservedValue: in.ObservedValue, Threshold: in.Threshold, Level: a.Level, Deviation: a.Deviation, ThresholdHit: a.ThresholdHit, Explanation: a.Explanation, At: now}}
	i.ValidationHits = append(i.ValidationHits, "来源前缀校验通过", fmt.Sprintf("时间漂移%d分钟，结论：%s", dr.Minutes, dr.Conclusion))
	i.ValidationHits = append(i.ValidationHits, fmt.Sprintf("来源可靠度%d/100，窗口%s，结论：%s", rel.Score, rel.Window, rel.Conclusion))
	if len(rel.Penalties) > 0 {
		i.ValidationHits = append(i.ValidationHits, "扣分明细："+strings.Join(rel.Penalties, "、"))
	}
	if i.SourcePendingVerification {
		i.AddEvent("source_review_required", in.CreatedBy, fmt.Sprintf("来源可靠度%d低于审查阈值%d，首个任务交由安全主管", rel.Score, in.SourceReviewThreshold))
	}
	if dr.Level != "normal" {
		i.ValidationHits = append(i.ValidationHits, fmt.Sprintf("漂移等级：%s", dr.Level))
	}
	i.AddEvent("incident_created", in.CreatedBy, fmt.Sprintf("环境异常登记；来源%s；漂移%d分钟；校验%s", in.Source, dr.Minutes, dr.Conclusion))
	tid := newID()
	due := Deadline(now, in.DueMinutes)
	assignee := in.Assignee
	if i.SourcePendingVerification {
		assignee = "安全主管"
	}
	i.Tasks[tid] = &casepkg.ResponseTask{ID: tid, IncidentID: id, Assignee: assignee, DueAt: due, Instruction: "检查展柜环境并采取降温/除湿措施", Status: "open", Revision: 1}
	i.AddEvent("task_assigned", in.CreatedBy, "处置任务已派发")
	if e = s.repo.Create(i); e != nil {
		return nil, a, e
	}
	if in.IdempotencyKey != "" {
		_ = s.repo.BindIdempotency(in.IdempotencyKey, id, fp)
	}
	return i, a, nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
func (s *Service) ClaimTask(id, tid, actor string) (*casepkg.EnvironmentIncident, error) {
	i, e := s.repo.Get(id)
	if e != nil {
		return nil, e
	}
	t, ok := i.Tasks[tid]
	if !ok {
		return nil, casepkg.ErrNotFound
	}
	if i.Status == casepkg.StatusClosed {
		return nil, casepkg.ErrConflict
	}
	if t.Status != "completed" && time.Now().UTC().After(t.DueAt) {
		t.Status = "overdue"
		t.OverdueMinutes = int(time.Since(t.DueAt).Minutes())
		t.SupervisorRequired = i.ImpactLevel == casepkg.ImpactHigh
	}
	if t.Status == "overdue" && i.ImpactLevel == casepkg.ImpactHigh && !isSupervisor(actor) {
		return nil, casepkg.ErrConflict
	}
	if t.Assignee != "" && t.Assignee != actor && !(t.Status == "overdue" && i.ImpactLevel == casepkg.ImpactHigh && isSupervisor(actor)) {
		return nil, fmt.Errorf("仅分派对象可领取任务")
	}
	if t.Status == "in_progress" {
		old := i.Revision
		s.updateReminder(i, t, actor)
		if i.Revision != old {
			return i, s.repo.Save(i, old)
		}
		return i, nil
	}
	if t.Status != "open" {
		return nil, casepkg.ErrConflict
	}
	old := i.Revision
	t.Status = "in_progress"
	t.ClaimedBy = actor
	if isSupervisor(actor) && t.SupervisorRequired {
		oldAssignee := t.Assignee
		t.Assignee = actor
		i.AddEvent("supervisor_takeover", actor, fmt.Sprintf("主管接管逾期任务，原责任人%s", oldAssignee))
	}
	claimedAt := time.Now().UTC()
	t.ClaimedAt = &claimedAt
	t.Revision++
	i.AddEvent("task_claimed", actor, "任务已领取")
	s.updateReminder(i, t, actor)
	return i, s.repo.Save(i, old)
}

func isSupervisor(actor string) bool {
	a := strings.ToLower(actor)
	return strings.Contains(actor, "主管") || strings.Contains(a, "supervisor") || strings.Contains(a, "manager")
}

func (s *Service) updateReminder(i *casepkg.EnvironmentIncident, t *casepkg.ResponseTask, actor string) {
	if t.Status == "completed" || i.Status == casepkg.StatusClosed {
		return
	}
	mins := time.Until(t.DueAt).Minutes()
	level := "none"
	if i.ImpactLevel == casepkg.ImpactHigh {
		if mins <= 5 {
			level = "escalated"
		} else if mins <= 15 {
			level = "warning"
		}
	}
	if level != t.ReminderLevel {
		t.ReminderLevel = level
		if level != "none" {
			i.AddEvent("task_reminder", actor, fmt.Sprintf("提醒级别%s，距截止%.0f分钟", level, mins))
		}
	}
	if mins < 0 {
		t.Status = "overdue"
		t.SupervisorRequired = i.ImpactLevel == casepkg.ImpactHigh
		if !t.OverdueNotified {
			t.OverdueNotified = true
			i.AddEvent("task_overdue", actor, "任务已逾期，需主管确认")
		}
	}
}
func (s *Service) CompleteTask(id, tid, actor, note string, measurements map[string]float64, confirms ...bool) (*casepkg.EnvironmentIncident, error) {
	supervisor := len(confirms) > 0 && confirms[0]
	if strings.TrimSpace(actor) == "" {
		return nil, fmt.Errorf("actor不能为空")
	}
	i, e := s.repo.Get(id)
	if e != nil {
		return nil, e
	}
	t, ok := i.Tasks[tid]
	if !ok {
		return nil, casepkg.ErrNotFound
	}
	if i.Status == casepkg.StatusClosed {
		return nil, casepkg.ErrConflict
	}
	if t.Status == "completed" {
		if evidenceFingerprint(actor, note, measurements) != t.EvidenceFingerprint {
			return nil, casepkg.ErrConflict
		}
		return i, nil
	}
	if t.Assignee != "" && t.Assignee != actor && !supervisor {
		return nil, fmt.Errorf("无权完成该任务")
	}
	if t.Status == "open" {
		return nil, fmt.Errorf("任务需先领取")
	}
	if t.Status == "overdue" && !supervisor {
		return nil, casepkg.ErrConflict
	}
	if time.Now().UTC().After(t.DueAt) && t.Status != "overdue" && !supervisor {
		old := i.Revision
		t.Status = "overdue"
		t.SupervisorRequired = i.ImpactLevel == casepkg.ImpactHigh
		i.AddEvent("task_overdue", actor, fmt.Sprintf("逾期%d分钟", int(time.Since(t.DueAt).Minutes())))
		_ = s.repo.Save(i, old)
		return nil, casepkg.ErrConflict
	}
	now := time.Now().UTC()
	if now.After(t.DueAt) && !supervisor {
		t.Status = "overdue"
		t.SupervisorRequired = i.ImpactLevel == casepkg.ImpactHigh
		old := i.Revision
		i.AddEvent("task_overdue", actor, "任务逾期，等待主管确认")
		_ = s.repo.Save(i, old)
		return nil, casepkg.ErrConflict
	}
	if strings.TrimSpace(note) == "" || len([]rune(note)) < 6 || !(strings.Contains(note, "措施") || strings.Contains(strings.ToLower(note), "measure")) || !(strings.Contains(note, "位置") || strings.Contains(strings.ToLower(note), "location")) || !(strings.Contains(note, "结果") || strings.Contains(strings.ToLower(note), "result")) {
		return nil, fmt.Errorf("evidence_note必须包含措施、位置和结果")
	}
	v := measurements[i.Metric]
	if _, ok := measurements[i.Metric]; !ok || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, fmt.Errorf("measurements.%s必须为有限数", i.Metric)
	}
	if !rules.PhysicalRange(i.Metric, v) {
		return nil, fmt.Errorf("measurements.%s超出物理范围", i.Metric)
	}
	old := i.Revision
	t.Status = "completed"
	t.EvidenceNote = note
	t.Measurements = measurements
	t.CompletedAt = &now
	t.CompletedBy = actor
	t.EvidenceFingerprint = evidenceFingerprint(actor, note, measurements)
	if now.Before(t.DueAt) || now.Equal(t.DueAt) {
		t.SLAHit = true
	} else {
		t.OverdueMinutes = int(now.Sub(t.DueAt).Minutes())
	}
	if t.ClaimedAt != nil {
		t.HandlingMinutes = now.Sub(*t.ClaimedAt).Minutes()
	}
	t.Revision++
	tol := math.Abs(i.Threshold) * 0.05
	if i.Sensitivity == "high" {
		tol = math.Abs(i.Threshold) * 0.03
	}
	if math.Abs(v-i.Threshold) > tol {
		t.NeedsFollowup = true
		t.FollowupHint = "复测未达标，请补充措施后再次复测"
		i.Status = casepkg.StatusInProgress
		// 同一证据指纹只生成一个补救任务。
		for _, existing := range i.Tasks {
			if existing.FollowupTaskID == t.ID || (existing.Instruction == "复测未达标补救" && existing.EvidenceFingerprint == t.EvidenceFingerprint) {
				t.FollowupTaskID = existing.ID
				break
			}
		}
		if t.FollowupTaskID == "" {
			fid := newID()
			due := Deadline(now, 60)
			if i.ImpactLevel == casepkg.ImpactHigh {
				due = now.Add(30 * time.Minute)
			} else if i.ImpactLevel == casepkg.ImpactMedium {
				due = now.Add(45 * time.Minute)
			}
			i.Tasks[fid] = &casepkg.ResponseTask{ID: fid, IncidentID: id, Assignee: t.Assignee, DueAt: due, Instruction: "复测未达标补救", Status: "open", Revision: 1, EvidenceFingerprint: t.EvidenceFingerprint}
			t.FollowupTaskID = fid
			i.AddEvent("followup_task_created", actor, fmt.Sprintf("复测偏差%.3f超出容差，已创建补救任务%s", math.Abs(v-i.Threshold), fid))
		}
		i.AddEvent("task_needs_followup", actor, fmt.Sprintf("复测偏差%.3f超出容差，阈值容差%.3f", math.Abs(v-i.Threshold), tol))
	} else {
		i.Status = casepkg.StatusVerifying
		i.AddEvent("task_completed", actor, "现场措施与证据已记录，复测达标")
	}
	return i, s.repo.Save(i, old)
}

func evidenceFingerprint(actor, note string, measurements map[string]float64) string {
	keys := make([]string, 0, len(measurements))
	for k := range measurements {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%s|", actor, note)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%.9g;", k, measurements[k])
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

func (s *Service) AdjustTask(id, tid, actor string, due time.Time, reason string, supervisor bool) (*casepkg.EnvironmentIncident, error) {
	return s.AdjustTaskWithAssignee(id, tid, actor, "", due, reason, supervisor)
}
func (s *Service) AdjustTaskWithAssignee(id, tid, actor, assignee string, due time.Time, reason string, supervisor bool) (*casepkg.EnvironmentIncident, error) {
	i, e := s.repo.Get(id)
	if e != nil {
		return nil, e
	}
	t, ok := i.Tasks[tid]
	if !ok {
		return nil, casepkg.ErrNotFound
	}
	if i.Status == casepkg.StatusClosed {
		return nil, casepkg.ErrConflict
	}
	if !supervisor && ((t.ClaimedBy != "" && t.ClaimedBy != actor) || (t.Assignee != "" && t.Assignee != actor)) {
		return nil, fmt.Errorf("仅任务领取者可调整截止时间")
	}
	if assignee != "" && assignee != t.Assignee && !supervisor {
		return nil, fmt.Errorf("仅主管可改派任务")
	}
	if due.Before(time.Now().UTC()) || strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("due_at必须晚于当前时间且原因不能为空")
	}
	sig := due.UTC().Format(time.RFC3339Nano) + "|" + reason
	if assignee != "" {
		sig += "|" + assignee
	}
	if t.LastAdjustment != "" {
		if t.LastAdjustment == sig {
			return i, nil
		}
		return nil, casepkg.ErrConflict
	}
	old := i.Revision
	prev := t.DueAt
	prevAssignee := t.Assignee
	t.DueAt = due
	if assignee != "" {
		t.Assignee = assignee
		t.ClaimedBy = assignee
	}
	t.LastAdjustment = sig
	t.AdjustmentHistory = append(t.AdjustmentHistory, fmt.Sprintf("%s/%s -> %s/%s by %s: %s", prevAssignee, prev.Format(time.RFC3339), t.Assignee, due.Format(time.RFC3339), actor, reason))
	t.AdjustmentActors = append(t.AdjustmentActors, actor)
	t.Revision++
	i.AddEvent("task_due_adjusted", actor, fmt.Sprintf("截止时间由%s调整为%s，原因：%s", prev.Format(time.RFC3339), due.Format(time.RFC3339), reason))
	return i, s.repo.Save(i, old)
}

func (s *Service) Reassess(id, sensitivity, actor string) (*casepkg.EnvironmentIncident, error) {
	return s.reassess(id, sensitivity, actor)
}

func (s *Service) ReassessWithKey(id, sensitivity, actor, key string) (*casepkg.EnvironmentIncident, bool, error) {
	if key == "" {
		i, e := s.reassess(id, sensitivity, actor)
		return i, false, e
	}
	fp := fmt.Sprintf("reassess|%s|%s", id, sensitivity)
	if oldID, oldFP, ok := s.repo.Idempotency("reassess:" + key); ok {
		if oldID != id || oldFP != fp {
			return nil, false, casepkg.ErrConflict
		}
		i, e := s.repo.Get(id)
		return i, true, e
	}
	i, e := s.reassess(id, sensitivity, actor)
	if e != nil {
		return nil, false, e
	}
	if e = s.repo.BindIdempotency("reassess:"+key, id, fp); e != nil {
		return nil, false, e
	}
	return i, false, nil
}

func (s *Service) reassess(id, sensitivity, actor string) (*casepkg.EnvironmentIncident, error) {
	i, e := s.repo.Get(id)
	if e != nil {
		return nil, e
	}
	if i.Status == casepkg.StatusClosed {
		return nil, casepkg.ErrConflict
	}
	if sensitivity == "" {
		sensitivity = i.Sensitivity
	}
	if sensitivity == i.Sensitivity && len(i.AssessmentHistory) > 1 {
		return nil, casepkg.ErrConflict
	}
	a, e := rules.Assess(i.Metric, i.ObservedValue, i.Threshold, sensitivity)
	if e != nil {
		return nil, e
	}
	old := i.Revision
	ver := fmt.Sprintf("r%d", old+1)
	previous := i.Assessment
	i.AssessmentHistory = append(i.AssessmentHistory, casepkg.AssessmentSnapshot{Version: i.RuleVersion, Sensitivity: i.Sensitivity, ObservedValue: i.ObservedValue, Threshold: i.Threshold, Level: previous.Level, Deviation: previous.Deviation, ThresholdHit: previous.ThresholdHit, Explanation: previous.Explanation, RecalculatedBy: actor, At: time.Now().UTC()})
	i.ImpactLevel = a.Level
	i.Sensitivity = sensitivity
	i.RuleVersion = ver
	i.Assessment = casepkg.AssessmentDetail{Level: a.Level, Deviation: a.Deviation, ThresholdHit: a.ThresholdHit, SensitivityAdjustment: a.SensitivityAdjustment, Explanation: a.Explanation}
	i.AssessmentHistory = append(i.AssessmentHistory, casepkg.AssessmentSnapshot{Version: ver, Sensitivity: sensitivity, ObservedValue: i.ObservedValue, Threshold: i.Threshold, Level: a.Level, Deviation: a.Deviation, ThresholdHit: a.ThresholdHit, Explanation: a.Explanation, RecalculatedBy: actor, At: time.Now().UTC()})
	i.AddEvent("assessment_recalculated", actor, fmt.Sprintf("规则%s：等级%s -> %s；旧解释%s；新解释%s", ver, previous.Level, a.Level, previous.Explanation, a.Explanation))
	if impactRank(a.Level) > impactRank(previous.Level) {
		i.AddEvent("risk_alert", actor, fmt.Sprintf("重评等级上调至%s", a.Level))
	}
	return i, s.repo.Save(i, old)
}
func (s *Service) Verify(id, reviewer string, samples []float64, note string) (*casepkg.EnvironmentIncident, *casepkg.VerificationRecord, error) {
	now := time.Now().UTC()
	return s.VerifyWindow(id, reviewer, samples, note, now.Add(-time.Duration(len(samples)-1)*time.Minute), now)
}
func (s *Service) VerifyWindow(id, reviewer string, samples []float64, note string, start, end time.Time) (*casepkg.EnvironmentIncident, *casepkg.VerificationRecord, error) {
	return s.VerifyWindowWithTimes(id, reviewer, samples, nil, note, start, end)
}

// VerifyWindowWithTimes 在保留旧入口的同时支持逐样本时间戳校验，避免用稀疏样本伪造连续恢复。
func (s *Service) VerifyWindowWithTimes(id, reviewer string, samples []float64, sampleTimes []time.Time, note string, start, end time.Time) (*casepkg.EnvironmentIncident, *casepkg.VerificationRecord, error) {
	i, e := s.repo.Get(id)
	if e != nil {
		return nil, nil, e
	}
	if i.Status == casepkg.StatusClosed {
		return nil, nil, casepkg.ErrConflict
	}
	buf := fmt.Sprintf("%s|%s|%s|%v|%v", start.UTC().Format(time.RFC3339Nano), end.UTC().Format(time.RFC3339Nano), reviewer, samples, sampleTimes)
	h := sha256.Sum256([]byte(buf))
	fp := hex.EncodeToString(h[:])
	for n := range i.Verifications {
		v := &i.Verifications[n]
		if v.Fingerprint == fp {
			return i, v, nil
		}
		if v.WindowStart.Equal(start) && v.WindowEnd.Equal(end) {
			if v.Reviewer == reviewer || fmt.Sprintf("%v", v.Samples) != fmt.Sprintf("%v", samples) {
				return nil, nil, casepkg.ErrConflict
			}
		}
	}
	if start.IsZero() || end.IsZero() {
		return nil, nil, fmt.Errorf("复核窗口不能为空")
	}
	if end.Before(start) || end.Sub(start) > 24*time.Hour {
		return nil, nil, fmt.Errorf("复核窗口无效")
	}
	if len(sampleTimes) > 0 {
		if len(sampleTimes) != len(samples) || !sampleTimes[0].Equal(start) || !sampleTimes[len(sampleTimes)-1].Equal(end) {
			return nil, nil, fmt.Errorf("样本时间序列必须覆盖窗口起止")
		}
		for n := 1; n < len(sampleTimes); n++ {
			if !sampleTimes[n].After(sampleTimes[n-1]) || (n > 1 && sampleTimes[n].Sub(sampleTimes[n-1].UTC()) != sampleTimes[1].Sub(sampleTimes[0].UTC())) {
				return nil, nil, fmt.Errorf("样本间隔不连续")
			}
		}
	} else if len(samples) > 1 {
		step := end.Sub(start) / time.Duration(len(samples)-1)
		if step <= 0 || end.Sub(start)%time.Duration(len(samples)-1) != 0 {
			return nil, nil, fmt.Errorf("样本间隔不连续")
		}
	}
	r, e := rules.VerifyDetailed(i.Metric, samples, i.Threshold, i.Sensitivity, start, end)
	if e != nil {
		return nil, nil, e
	}
	if r.Passed && i.OpenTasks() > 0 {
		return nil, nil, fmt.Errorf("仍有未完成任务，暂不能关闭事件")
	}
	old := i.Revision
	now := time.Now().UTC()
	base := 0.0
	maxVar := 0.0
	for _, t := range i.Tasks {
		if len(t.Measurements) > 0 {
			if v, ok := t.Measurements[i.Metric]; ok {
				base = v
				break
			}
		}
	}
	for _, v := range samples {
		if d := math.Abs(v - base); d > maxVar {
			maxVar = d
		}
	}
	if len(sampleTimes) == 0 {
		sampleTimes = make([]time.Time, len(samples))
		if len(samples) == 1 {
			sampleTimes[0] = start
		} else {
			step := end.Sub(start) / time.Duration(len(samples)-1)
			for n := range samples {
				sampleTimes[n] = start.Add(time.Duration(n) * step)
			}
		}
	}
	vr := casepkg.VerificationRecord{ID: newID(), IncidentID: id, WindowStart: start, WindowEnd: end, Samples: append([]float64(nil), samples...), SampleTimes: append([]time.Time(nil), sampleTimes...), Criteria: r.Criteria, Passed: r.Passed, Reviewer: reviewer, ReviewedAt: now, Note: note, BaselineDeviation: math.Abs(samples[0] - base), MaxVariation: maxVar, NeedsExtendedWindow: maxVar > math.Abs(i.Threshold)*.1, FirstOutOfRange: r.FirstOutOfRange, Fingerprint: fp}
	if r.FirstOutOfRange != nil {
		vr.FailureReason = "首个越界样本"
	} else if maxVar > math.Abs(i.Threshold)*.1 {
		vr.FailureReason = "最大波动超限"
	} else if !r.Passed {
		vr.FailureReason = "恢复容差未满足"
	}
	if len(i.Verifications) > 0 {
		prev := i.Verifications[len(i.Verifications)-1]
		if vr.BaselineDeviation > prev.BaselineDeviation || vr.MaxVariation > prev.MaxVariation {
			vr.Trend = "恶化"
		} else if vr.BaselineDeviation < prev.BaselineDeviation && vr.MaxVariation < prev.MaxVariation {
			vr.Trend = "改善"
		} else {
			vr.Trend = "稳定"
		}
	}
	i.Verifications = append(i.Verifications, vr)
	independentRequired := r.Passed && (i.ImpactLevel == casepkg.ImpactHigh || i.Sensitivity == "high")
	if independentRequired {
		for _, prev := range i.Verifications[:len(i.Verifications)-1] {
			if prev.Passed && prev.Reviewer == reviewer {
				return nil, nil, casepkg.ErrConflict
			}
		}
	}
	passedReviewers := map[string]bool{}
	for _, prev := range i.Verifications {
		if prev.Passed {
			passedReviewers[prev.Reviewer] = true
		}
	}
	canClose := r.Passed && i.OpenTasks() == 0 && (!independentRequired || len(passedReviewers) >= 2)
	if r.Passed && independentRequired && len(passedReviewers) < 2 {
		i.Status = casepkg.StatusVerifying
		i.AddEvent("verification_second_required", reviewer, "高敏感或高影响事件需要第二名独立复核人")
	} else if canClose {
		i.Status = casepkg.StatusClosed
		i.AddEvent("verification_passed", reviewer, r.Criteria)
		chain := []string{i.CreatedBy}
		for _, t := range i.Tasks {
			if t.ClaimedBy != "" {
				chain = append(chain, t.ClaimedBy)
			}
			chain = append(chain, t.AdjustmentActors...)
			if t.CompletedAt != nil {
				chain = append(chain, t.CompletedBy)
			}
		}
		chain = append(chain, reviewer)
		seen := map[string]bool{}
		uniq := make([]string, 0, len(chain))
		for _, a := range chain {
			if a != "" && !seen[a] {
				seen[a] = true
				uniq = append(uniq, a)
			}
		}
		i.Audit = &casepkg.AuditSummary{IncidentID: id, ClosedAt: now, Decision: "closed", TimelineHash: i.TimelineHash(), ActorChain: uniq, OpenTaskCount: 0, SummaryText: "环境恢复复核通过，事件已关闭", TimelineSnapshot: append([]casepkg.TimelineEvent(nil), i.Timeline...)}
		i.Audit.TimelineHash = i.TimelineHash()
	} else if !r.Passed {
		i.FailureCount++
		i.ValidationHits = append(i.ValidationHits, fmt.Sprintf("复核失败：%s", vr.FailureReason))
		i.Status = casepkg.StatusReopened
		if !r.Passed {
			i.AddEvent("verification_failed", reviewer, r.Criteria)
			if i.FailureCount >= s.MaxReopens {
				i.Status = casepkg.StatusReopened
				i.AddEvent("incident_escalated", reviewer, "达到最大重开次数，需主管确认")
			} else {
				tid := newID()
				due := Deadline(now, 60)
				if i.FailureCount >= 2 {
					i.ImpactLevel = casepkg.ImpactMedium
					due = now.Add(30 * time.Minute)
				}
				i.Tasks[tid] = &casepkg.ResponseTask{ID: tid, IncidentID: id, Assignee: reviewer, DueAt: due, Instruction: "复核未通过，请继续处置并补充措施", Status: "open", Revision: 1}
				i.AddEvent("reopen_task_created", reviewer, fmt.Sprintf("失败复核%d，已创建补救任务", i.FailureCount))
			}
		}
	}
	if e = s.repo.Save(i, old); e != nil {
		return nil, nil, e
	}
	return i, &vr, nil
}

type ListFilter struct {
	VenueID, Zone  string
	Status         casepkg.IncidentStatus
	Impact         casepkg.ImpactLevel
	From, To       time.Time
	Page, PageSize int
	Sort           string
	Assignee       string
	TaskStatus     string
	OverdueOnly    bool
}

func (s *Service) List(f ListFilter) ([]*casepkg.EnvironmentIncident, int, int, int, map[string]int, error) {
	x, total, open, high, counts, _, e := s.ListDetailed(f)
	return x, total, open, high, counts, e
}

type RiskGroup struct {
	VenueID  string `json:"venue_id"`
	Zone     string `json:"zone"`
	Low      int    `json:"low"`
	Medium   int    `json:"medium"`
	High     int    `json:"high"`
	Unclosed int    `json:"unclosed"`
}

func (s *Service) ListDetailed(f ListFilter) ([]*casepkg.EnvironmentIncident, int, int, int, map[string]int, []RiskGroup, error) {
	all, e := s.repo.List()
	if e != nil {
		return nil, 0, 0, 0, nil, nil, e
	}
	x := make([]*casepkg.EnvironmentIncident, 0)
	for _, i := range all {
		if f.VenueID != "" && i.VenueID != f.VenueID || f.Zone != "" && i.Zone != f.Zone || f.Status != "" && i.Status != f.Status || f.Impact != "" && i.ImpactLevel != f.Impact || !f.From.IsZero() && i.ObservedAt.Before(f.From) || !f.To.IsZero() && i.ObservedAt.After(f.To) {
			continue
		}
		if f.Assignee != "" || f.TaskStatus != "" || f.OverdueOnly {
			matched := false
			for _, t := range i.Tasks {
				if f.Assignee != "" && t.Assignee != f.Assignee {
					continue
				}
				if f.TaskStatus != "" && t.Status != f.TaskStatus {
					continue
				}
				if f.OverdueOnly && (t.CompletedAt != nil || time.Now().UTC().Before(t.DueAt)) {
					continue
				}
				matched = true
				t.OverdueMinutes = int(time.Since(t.DueAt).Minutes())
				if t.OverdueMinutes < 0 {
					t.OverdueMinutes = 0
				}
				if t.OverdueMinutes > 0 && i.ImpactLevel == casepkg.ImpactHigh {
					t.SupervisorRequired = true
				}
			}
			if !matched {
				continue
			}
		}
		x = append(x, i)
	}
	sort.Slice(x, func(a, b int) bool {
		if f.OverdueOnly {
			ra, rb := impactRank(x[a].ImpactLevel), impactRank(x[b].ImpactLevel)
			if ra != rb {
				return ra > rb
			}
			ma, mb := earliestOverdue(x[a]), earliestOverdue(x[b])
			if ma != mb {
				return ma > mb
			}
		}
		if f.Sort == "impact" && x[a].ImpactLevel != x[b].ImpactLevel {
			return impactRank(x[a].ImpactLevel) > impactRank(x[b].ImpactLevel)
		}
		if f.Sort == "deviation" && x[a].Assessment.Deviation != x[b].Assessment.Deviation {
			return x[a].Assessment.Deviation > x[b].Assessment.Deviation
		}
		if f.Sort == "observed_at" { /* fall through to time ordering */
		}
		if x[a].ObservedAt.Equal(x[b].ObservedAt) {
			return x[a].ID < x[b].ID
		}
		return x[a].ObservedAt.After(x[b].ObservedAt)
	})
	total := len(x)
	open, high := 0, 0
	counts := map[string]int{}
	for _, i := range x {
		counts[string(i.Status)]++
		if i.Status != casepkg.StatusClosed {
			open++
		}
		if i.ImpactLevel == casepkg.ImpactHigh {
			high++
		}
	}
	page := f.Page
	if page < 1 {
		page = 1
	}
	size := f.PageSize
	if size <= 0 {
		size = 20
	}
	start := (page - 1) * size
	if start > len(x) {
		start = len(x)
	}
	end := start + size
	if end > len(x) {
		end = len(x)
	}
	gm := map[string]*RiskGroup{}
	for _, i := range x {
		k := i.VenueID + "\x00" + i.Zone
		g := gm[k]
		if g == nil {
			g = &RiskGroup{VenueID: i.VenueID, Zone: i.Zone}
			gm[k] = g
		}
		switch i.ImpactLevel {
		case casepkg.ImpactLow:
			g.Low++
		case casepkg.ImpactMedium:
			g.Medium++
		case casepkg.ImpactHigh:
			g.High++
		}
		if i.Status != casepkg.StatusClosed {
			g.Unclosed++
		}
	}
	groups := make([]RiskGroup, 0, len(gm))
	for _, g := range gm {
		groups = append(groups, *g)
	}
	sort.Slice(groups, func(a, b int) bool {
		if groups[a].VenueID == groups[b].VenueID {
			return groups[a].Zone < groups[b].Zone
		}
		return groups[a].VenueID < groups[b].VenueID
	})
	return x[start:end], total, open, high, counts, groups, nil
}
func earliestOverdue(i *casepkg.EnvironmentIncident) int {
	m := 0
	for _, t := range i.Tasks {
		if t.CompletedAt == nil && time.Now().UTC().After(t.DueAt) {
			x := int(time.Since(t.DueAt).Minutes())
			if x > m {
				m = x
			}
		}
	}
	return m
}
func impactRank(v casepkg.ImpactLevel) int {
	switch v {
	case casepkg.ImpactHigh:
		return 3
	case casepkg.ImpactMedium:
		return 2
	default:
		return 1
	}
}
func (s *Service) Audit(id string) (*casepkg.AuditSummary, bool, error) {
	i, e := s.repo.Get(id)
	if e != nil {
		return nil, false, e
	}
	if i.Audit == nil {
		return nil, false, casepkg.ErrNotFound
	}
	expected := i.TimelineHash()
	return i.Audit, expected == i.Audit.TimelineHash, nil
}
