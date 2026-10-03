# x86-64 `.eh_frame` 值班分析台

飞控固件异常后，值班工程师在页面粘贴**不超过 192 KiB** 的 Base64
小端 ELF64 `.eh_frame` 原始节，填写当前 PC 与寄存器值（以及供
`offset` 恢复使用的内存快照），即可通过真实 HTTP 接口查看：

* 命中的 FDE、关联 CIE、命中范围（半开区间）；
* CFA 规则与取值、调用者 PC；
* 各寄存器的恢复规则（offset / same_value / undefined / register）、
  规则来源的**原始节偏移**与恢复取值；
* 逐地址归约时间线（含 `remember_state` / 规则改写 / `restore_state`）。

在页面勾选**连续回溯**并填写 **2–16 帧上限**后，系统以同一份
`.eh_frame`、寄存器与内存快照逐帧取得调用者：先按既有规则归约当前帧，
再仅以该帧恢复出的寄存器（按 DWARF 定义，下一帧 `rsp` 取本帧 CFA）
与调用者 PC 作为下一帧输入；逐帧展示命中的 FDE、CFA、调用者 PC、
恢复规则、所用内存读取与下一帧输入。调用者 PC 未命中 FDE 时作为
**正常链尾**保留此前完整帧；PC 未推进、重复落入同一调用状态（循环）
或达到帧上限时明确给出终止原因；任一后续帧出现内存越界、调用者 PC
不可恢复或格式错误时，整条连续回溯 **422 拒绝、不返回任何帧**，
并定位失败帧号与首个原始节偏移。

## 支持的方言（严格子集）

| 项目 | 范围 |
| --- | --- |
| 记录格式 | 32 位 DWARF `.eh_frame`，小端 |
| CIE | version 1 |
| FDE 的 CIE 指针 | **绝对 32 位**（目标 CIE 长度字段的节内字节偏移） |
| CFA 指令 | `def_cfa` / `def_cfa_register` / `def_cfa_offset` |
| 寄存器规则 | `offset`（含高位紧凑形式与 extended）、`restore`、`same_value`、`undefined`、`register` |
| 地址推进 | `advance_loc` / `advance_loc1/2/4`、`set_loc`（绝对 32 位） |
| 规则快照 | `remember_state` / `restore_state` |

不支持：DWARF64、CIE version ≠ 1、增强数据解释（'z' 块仅做长度校验后跳过）、
expression 规则等。出现这些情况会在**首个原始偏移**处明确报错。

## 安全归约保证

1. **CIE 初始规则 + FDE 指令逐地址归约**：行边界由地址推进指令提交，
   行内规则修改作用于当前行；`set_loc` 按 FDE 初始位置换算相对位置。
2. **remember/restore 语义**：快照只保存规则（含 CFA），**不保存位置**；
   对于包含 `remember_state`、规则改写和 `restore_state` 的 FDE，较晚
   PC 的证据会回退到保存时的规则。
3. **未命中即清除**：PC 不落入任何 FDE 的 `[start, start+range)` 半开区间
   （包括 PC 恰为结束地址）时返回 `hit=false`，响应不含任何上次成功的
   CFA/调用者 PC/寄存器结论。
4. **无部分结果**：悬空 CIE 引用、记录长度越界、截断的 ULEB128/SLEB128、
   规则栈下溢、CIE version 错误、CFA 所需寄存器缺失、**CFA 或 offset
   内存读取越界**（地址不在用户提供的内存快照内）、调用者 PC 不可恢复
   （返回地址列无规则或为 undefined），都在首个原始偏移处整体拒绝，
   绝不返回部分寄存器结果。

> 由于 `.eh_frame` 的 CIE 标记字也是 `0`，而本系统又接受指向节偏移 0
> 处 CIE 的绝对指针 `0`，解析器通过**结构性探测**消歧：节中第一条记录
> 必须是 CIE；其后 id 为 0 的记录，仅当字节能构成合法 CIE 头
> （version=1、增强字符串正常结束、code/data align 合法）时才判定为 CIE，
> 否则视为指向偏移 0 的 FDE。

## 运行（Docker Compose）

```bash
# 默认宿主端口 8080
docker compose up -d --build
# 自定义宿主端口
EHF_HOST_PORT=9090 docker compose up -d --build

# 页面
open http://localhost:8080/
# 健康响应
curl -s http://localhost:8080/healthz
```

## 验收 verify（Compose 内对真实接口执行）

`verify` 在 Compose 内：构建检查（字节码编译）、对有效嵌套规则 /
恢复回退 / 截断 FDE 执行代码测试，覆盖连续回溯的**有效多帧链、正常
未命中链尾、PC 未推进、循环终止、帧上限与后续帧失败清空链路**，并以
有效及失败输入完成 API/HTTP 冒烟后退出，**用退出码报告验收结果**
（0 全部通过，1 存在失败）：

```bash
docker compose up -d --build web
docker compose run --rm verify
echo "exit=$?"
```

`verify` 会等待 `web` 健康后，通过 `EHF_SMOKE_URL=http://web:8080`
对真实 HTTP 接口做冒烟。也可不依赖容器本地直接运行（自行拉起进程内
HTTP 服务）：

```bash
python3 -m app.verify
```

## HTTP API

### `GET /healthz`

```json
{"status": "ok", "service": "eh-frame-analyzer"}
```

### `POST /api/analyze`

请求字段：

```json
{
  "section_base64": "....",
  "pc": "0x401003",
  "registers_text": "rsp=0x1000\nrbp=0x2000",
  "memory_text": "0x1008=0x50000"
}
```

也接受对象形式 `registers` / `memory`（键为寄存器名或编号）。
寄存器名兼容 `rax rdx rcx rbx rsi rdi rbp rsp r8..r15 rip`（DWARF
x86-64 编号 0..16）。

**单帧模式**（不带 `max_frames`）：成功命中时返回 200，包含 `fde /
cie / hit_range / matched_row / cfa / caller_pc / caller_pc_rule /
registers / memory_reads / timeline`；未命中返回 200 且仅
`hit=false + miss_reason`；任何解析/归约错误返回 **422**：

```json
{"error": "悬空 CIE 引用：FDE@0x12 的绝对指针 0xdead 不指向任何 CIE",
 "offset": 22}
```

`offset` 即检测到的首个原始节字节偏移，且错误响应不含寄存器结果。

**连续回溯模式**（额外提供 `"max_frames": N`，`2 ≤ N ≤ 16`）：

```json
{
  "mode": "chain",
  "pc": 4198400,
  "frame_limit": 8,
  "frame_count": 3,
  "stop_reason": "caller_pc_miss",
  "stop_reason_text": "调用者 PC 未命中 FDE（正常链尾）",
  "stop_detail": "帧 2 恢复出的调用者 PC 0x404000 未落入任何 FDE …",
  "frames": [
    { "frame_index": 0,
      "pc": 4198400, "fde": {…}, "cie": {…}, "cfa": {…},
      "caller_pc": 4202496, "caller_pc_rule": "…",
      "registers": […], "memory_reads": […], "timeline": […],
      "next_frame_input_registers": {"rsp": 4104} }
  ]
}
```

`frames[]` 每一项就是单帧命中响应的完整证据（另加 `frame_index` 与
`next_frame_input_registers`）。`next_frame_input_registers` 只列本帧
恢复出、确实喂给下一帧归约的寄存器（按 DWARF，下一帧 `rsp` 取本帧
CFA；返回地址列不作为寄存器，其恢复值即下一帧 PC，已由
`caller_pc` 单独承担）。`stop_reason` 取值：

| code | 含义 |
| --- | --- |
| `caller_pc_miss` | 调用者 PC 未命中任何 FDE，**正常链尾**，保留此前全部帧 |
| `pc_not_advanced` | 恢复出的调用者 PC 与当前 PC 相同，PC 未推进 |
| `duplicate_state` | 重复落入此前出现过的同一调用状态（PC+恢复寄存器集合），判为循环 |
| `frame_limit` | 已达到帧上限，末帧调用者仍可继续但未再归约 |

帧 0 起始 PC 未命中时返回与单帧一致的 `{"hit": false, …}`。任一
**后续帧**归约失败（内存越界、调用者 PC 不可恢复、格式错误等）返回
**422**，响应只含错误信息、`frame_index`（失败帧号）、`frame_pc` 与
该帧的首个原始节 `offset`，**不含 `frames`、不返回部分链路**；
`max_frames` 越界（不在 2–16）为 **400** 请求错误。

示例数据：`GET /chain_sample` 返回可直接粘贴的连续回溯示例负载。

## 目录

```
app/
  eh_frame.py    严格解析器 + CFI 抽象机 + 逐地址规则归约与状态恢复 + 连续回溯
  server.py      标准库 HTTP 服务（页面 / healthz / api/analyze）
  static/index.html  值班页面（单帧分析与 2–16 帧连续回溯）
  samplegen.py   确定性合成 .eh_frame（含 remember/restore、畸形与连续回溯样例）
  verify.py      构建检查 + 引擎代码测试（含连续回溯）+ API/HTTP 冒烟，退出码报告
Dockerfile
docker-compose.yml
```

仅依赖 Python 3.11 标准库，镜像内无 pip 安装步骤。
