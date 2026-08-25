# BENZHI_README

## 项目说明
- 项目：benzhi-project-4238d949-0cfc-419c-96d9-c30cb991e6cf
- 项目用途：展馆环境异常处置台提供环境越限事件从登记、影响评估、任务派发、现场措施、恢复复核到审计关闭的完整闭环。
- Go 工具链：`golang:1.22`
- 前端工具链：无

## 项目描述
- 项目名称：展馆环境异常处置台
- 项目介绍：面向博物馆与档案馆值守人员的环境异常处置服务，将温湿度或光照越限事件从发现、评估、派工、措施记录、恢复复核推进到审计关闭，形成可追踪的单一闭环。
- 项目概述：面向博物馆与档案馆值守人员的环境异常处置服务，将温湿度或光照越限事件从发现、评估、派工、措施记录、恢复复核推进到审计关闭，形成可追踪的单一闭环。
- 核心工作流：监测事件登记→影响评估→处置任务派发→现场措施记录→环境恢复复核→审计关闭
- 对外接口：HTTP JSON API 提供事件、任务、复核和审计摘要接口；服务支持 -addr=127.0.0.1:<port> 或 PORT 环境变量，默认监听 127.0.0.1:19081

## 标准构建、运行和测试命令
进入容器后执行：
cd '/app' && GOTOOLCHAIN=local go build ./...

cd /app && GOTOOLCHAIN=local go run ./cmd/envresponse -addr=127.0.0.1:19081

cd '/app' && GOTOOLCHAIN=local go test ./...

## Docker 构建和进入容器
chmod +x build_benzhi_docker.sh

./build_benzhi_docker.sh benzhi-project-4238d949-0cfc-419c-96d9-c30cb991e6cf-amd64 linux/amd64

./build_benzhi_docker.sh benzhi-project-4238d949-0cfc-419c-96d9-c30cb991e6cf-arm64 linux/arm64

docker run -it benzhi-project-4238d949-0cfc-419c-96d9-c30cb991e6cf-amd64:latest

## 题目验证命令
1. 预期退出码 0：`go test ./...`
2. 预期退出码 0：`go run ./cmd/envresponse -addr=127.0.0.1:19081 -self-check`
