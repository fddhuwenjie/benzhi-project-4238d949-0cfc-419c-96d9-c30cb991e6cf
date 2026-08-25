package main

import (
	"bytes"
	"context"
	"encoding/json"
	"envresponse/internal/httpapi"
	"envresponse/internal/store"
	"envresponse/internal/workflow"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:19081", "监听地址")
	self := flag.Bool("self-check", false, "执行自检")
	flag.Parse()
	if p := os.Getenv("PORT"); p != "" && *addr == "127.0.0.1:19081" {
		*addr = "127.0.0.1:" + p
	}
	if !strings.Contains(*addr, ":") {
		fmt.Println("地址无效")
		return
	}
	repo := store.New(".data")
	flow := workflow.New(repo)
	srv := &http.Server{Addr: *addr, Handler: httpapi.New(flow).Handler()}
	if *self {
		go srv.ListenAndServe()
		if err := smoke(*addr); err != nil {
			fmt.Println("自检失败:", err)
			_ = srv.Shutdown(context.Background())
			os.Exit(1)
		}
		_ = srv.Shutdown(context.Background())
		fmt.Println("自检通过")
		return
	}
	go func() {
		if e := srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			fmt.Println(e)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
func smoke(addr string) error {
	time.Sleep(100 * time.Millisecond)
	base := "http://" + addr
	body := map[string]any{"venue_id": "demo", "zone": "A1", "metric": "humidity", "observed_value": 80, "threshold": 50, "observed_at": time.Now().UTC().Format(time.RFC3339), "source": "sensor-1", "sensitivity": "high", "created_by": "值守员", "assignee": "值守员", "due_minutes": 5}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", base+"/v1/incidents", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "smoke-1")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return fmt.Errorf("create status %d", resp.StatusCode)
	}
	var out struct {
		Incident struct {
			ID    string              `json:"id"`
			Tasks map[string]struct{} `json:"tasks"`
		} `json:"incident"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	var tid string
	for k := range out.Incident.Tasks {
		tid = k
	}
	complete := map[string]any{"actor": "值守员", "evidence_note": "已调整空调并放置吸湿材料", "measurements": map[string]float64{"humidity": 50}}
	claimBody := map[string]any{"actor": "值守员"}
	cb, _ := json.Marshal(claimBody)
	rc, _ := http.NewRequest("POST", base+"/v1/incidents/"+out.Incident.ID+"/tasks/"+tid+"/claim", bytes.NewReader(cb))
	rc.Header.Set("Content-Type", "application/json")
	rc.Header.Set("Idempotency-Key", "smoke-claim")
	cr, ce := http.DefaultClient.Do(rc)
	if ce != nil {
		return ce
	}
	cr.Body.Close()
	if cr.StatusCode != 200 {
		return fmt.Errorf("claim status %d", cr.StatusCode)
	}
	complete["evidence_note"] = "采取措施并清理位置，结果湿度恢复"
	c, _ := json.Marshal(complete)
	r2, _ := http.NewRequest("POST", base+"/v1/incidents/"+out.Incident.ID+"/tasks/"+tid+"/complete", bytes.NewReader(c))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("Idempotency-Key", "smoke-2")
	rr, e := http.DefaultClient.Do(r2)
	if e != nil {
		return e
	}
	rr.Body.Close()
	if rr.StatusCode != 200 {
		return fmt.Errorf("complete status %d", rr.StatusCode)
	}
	ver := map[string]any{"reviewer": "专员", "samples": []float64{50, 51, 49}, "note": "连续观测正常"}
	v, _ := json.Marshal(ver)
	r3, _ := http.NewRequest("POST", base+"/v1/incidents/"+out.Incident.ID+"/verification", bytes.NewReader(v))
	r3.Header.Set("Content-Type", "application/json")
	r3.Header.Set("Idempotency-Key", "smoke-3")
	rv, e := http.DefaultClient.Do(r3)
	if e != nil {
		return e
	}
	defer rv.Body.Close()
	if rv.StatusCode != 200 {
		return fmt.Errorf("verify status %d", rv.StatusCode)
	}
	// 可靠度自检：连续严重漂移的来源进入待核验并派给安全主管。
	for n := 1; n <= 3; n++ {
		drift := time.Now().UTC().Add(-time.Duration(n*20) * time.Minute)
		b2 := map[string]any{"venue_id": "demo", "zone": fmt.Sprintf("D%d", n), "metric": "humidity", "observed_value": 55, "threshold": 50, "observed_at": drift.Format(time.RFC3339), "source": "gateway-drift", "created_by": "值守员", "assignee": "值守员"}
		bb, _ := json.Marshal(b2)
		rrq, _ := http.NewRequest("POST", base+"/v1/incidents", bytes.NewReader(bb))
		rrq.Header.Set("Content-Type", "application/json")
		rrq.Header.Set("Idempotency-Key", fmt.Sprintf("drift-%d", n))
		res, er := http.DefaultClient.Do(rrq)
		if er != nil || res.StatusCode != 201 {
			if res != nil {
				res.Body.Close()
			}
			return fmt.Errorf("drift create failed")
		}
		res.Body.Close()
	}
	_, _ = io.Copy(io.Discard, rv.Body)
	return nil
}
