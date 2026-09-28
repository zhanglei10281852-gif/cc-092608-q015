# 5G-A 场景加速运营服务

这是一个面向运营商网络优化与产品运营团队的 Python 后端，用于管理高铁、地铁、演唱会和大型场馆中的应用体验采样、质差识别、动态加速、用户权益、策略版本、容量预留与运营审计。服务使用 FastAPI 与 SQLite，所有运行数据保存在单个本地数据库文件中，不依赖另行部署的数据库、缓存、消息队列或浏览器界面。

## 已有能力

- 场景与区段：维护高铁线路、地铁区段、演唱会和场馆的容量、顺序、停留时间及运行状态。
- 应用画像：按游戏、直播、视频通话、视频和办公类别保存时延、丢包、上下行速率与优先级目标。
- 策略版本：校验质差评分权重、严重度阈值、资源倍数和会话时长，支持草稿、发布、生效与退役状态。
- 体验样本：使用业务采样键进行幂等写入，保存脱敏用户标识、终端类型、速度和网络指标。
- 质差事件：将应用目标与实测指标进行确定性比较，记录原因、严重度和处理状态。
- 动态加速：校验用户权益与生效策略，按区段容量预留上下行资源，支持完成、取消和超时释放。
- 运营分析：提供场景与应用质差率、容量利用率、会话成效和可恢复事件游标。
- 分级保留与去关联：按类别保留期限计算到期批次，将到期标识替换为不可逆、批次隔离的统计键，支持法律保全暂缓、活动争议暂缓、检查点续跑与证明报告。
- 身份与审计：提供管理员初始化、用户、角色、会话、权限、操作审计和后台维护能力。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/network-acceleration.db`。可以复制 `.env.example` 并通过 `NETWORK_DATABASE_PATH` 指定其他本地路径。

## 数据库初始化与检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

5G-A 运营接口统一使用 `/api/network` 前缀，场景、应用、策略、权益、样本、事件、会话和分析报告都在该路径下。

## 测试

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest
```

测试覆盖身份初始化、角色权限、审计脱敏、场景与应用登记、策略发布、样本幂等、质差判定、权益校验、容量拒绝、会话完成、固定时钟过期恢复和分析游标。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 与 CLI 冒烟

```bash
python -m app.cli smoke
python -m app.cli network-demo
```

`smoke` 在进程内检查根路径、健康接口和运营摘要；`network-demo` 会创建高铁场景、应用画像与策略，登记有效权益，写入一条质差样本并启动加速会话。

## 目录结构

```text
app/
  network/         场景、应用、策略、采样、质差、加速、容量和分析
  api/             用户、角色、认证、审计、系统与维护接口
  core/            时钟、安全、异常、隐私和分页能力
  repositories/    通用 SQLite 查询与身份持久化
  schemas/         身份与管理接口输入模型
  services/        认证、审计、用户、后台任务和维护服务
  cli.py           初始化、检查和业务冒烟入口
  database.py      SQLite 连接、基础表结构与权限初始化
tests/             核心、身份、网络运营和分析回归测试
tools/             本地维护脚本
```

## 数据一致性

SQLite 连接启用外键、WAL、busy timeout 和同步写入策略。策略发布、样本与事件创建、容量预留、会话终止和过期恢复使用即时事务。体验样本保存脱敏用户标识，登录令牌只保存摘要，审计和会话事件不会记录明文密码或令牌。

## 分级保留与去关联

合规要求网络体验数据只在排障期限内保留可关联旅客的标识，超期后仍可用于场景与应用统计，但不能还原到单个旅客。系统按三类数据分别计算到期批次：

| 类别 | 表 | 锚点时间 | 默认保留 | 暂缓条件 |
| --- | --- | --- | --- | --- |
| 体验样本 | `experience_samples` | `observed_at` | 30 天 | 关联质差事件处于 `open`/`accelerating`；法律保全 |
| 加速会话 | `acceleration_sessions` | `ended_at` | 90 天 | 会话 `active` 或关联事件未关闭；法律保全 |
| 用户权益 | `subscriber_entitlements` | `updated_at` | 180 天 | 权益处于 `active`/`suspended`；法律保全 |

到期批次为锚点时间加保留天数后所属的 UTC 月份。处理时只把 `subscriber_hash` 替换成统计键，外键、容量预留、质差事件和策略版本关联全部保留，审计链不断。统计键形如 `stat:v1:2026-08:<hmac>`：

- 使用服务端 pepper 做 HMAC-SHA256，不可逆，键内不含原始标识；
- 同一旅客在同一到期批次内跨样本、会话、权益得到相同键，保留行级同人关联；
- 不同到期批次键不同，无法跨批次还原同一旅客。

接口（均在 `/api/network/retention` 下，需要登录与相应权限）：

- `POST /preview` 预演：给出各类别候选、到期批次分布、跳过原因、表与聚合校验哈希，不改任何数据。
- `POST /apply` 执行：按页提交并推进检查点，传相同 `run_id` 可在中断后续跑；完成后返回证明报告。
- `GET /runs/{run_id}/attestation` 取回证明报告；`GET /runs` 列出任务。
- `GET /identity?subscriber_hash=...` 身份查询：执行后到期数据按原标识应查不到，但聚合报表数值不变。
- `POST /legal-holds`、`GET /legal-holds`、`POST /legal-holds/{id}/release` 管理旅客级或全局法律保全。

证明报告包含各表处理数量、跳过原因（保留期内/法律保全/活动争议）、每表基线与最终 SHA-256、质差/容量/策略关联表未改动标记、与标识无关的聚合口径哈希（执行前后必须一致）、到期未处理余数和整份报告的 `report_digest`。

CLI 对应命令：

```bash
python -m app.cli retention-preview --actor compliance --run-id rr-2026-09
python -m app.cli retention-apply  --actor compliance --run-id rr-2026-09
python -m app.cli retention-attest rr-2026-09
```

