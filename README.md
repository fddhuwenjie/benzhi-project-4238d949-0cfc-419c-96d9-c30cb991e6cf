# 展馆环境异常处置台

面向博物馆与档案馆值守人员的环境异常闭环服务，支持事件登记、影响评估、任务派发、现场措施留痕、恢复复核和审计关闭。服务提供 HTTP JSON API，默认仅监听 `127.0.0.1:19081`，可通过 `-addr` 或 `PORT` 配置。

标准命令：

`go test ./...`

`go run ./cmd/envresponse -addr=127.0.0.1:19081 -self-check`

启动常驻服务：`go run ./cmd/envresponse -addr=127.0.0.1:19081`

事件列表支持 `assignee`、`task_status`、`overdue_only=true` 筛选；登记响应包含来源可靠度与分区累计暴露快照。高敏感/高影响事件在关闭前需要两名独立复核人，复测不达标会自动生成补救任务。
