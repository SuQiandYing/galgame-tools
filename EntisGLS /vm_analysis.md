# EntisGLS / Cotopha 格式分析与证据台账

## 代码与数据的分界

工具代码不含任何作品专属字面量。作品相关的事实全部写在 `profiles/*.json`：

| 内容 | 位置 |
|---|---|
| 封包密码 | `profiles/*.json` 的 `archive_keys.keys` |
| 调用参数槽位的文本角色 | `profiles/*.json` 的 `call_slot_roles.calls` |
| 容器布局、指令编码、BSHF 算法 | `opcodelist.py` / `noa.py`（跨作品共用） |

适配新作品只需追加一份数据档。数据档缺失或为空时工具仍可运行：未加密封包照常
解包，加密封包提示需要密码，未声明的调用其字符串一律标 `misc` / `unresolved`，
不会凭外观猜测角色。

## 样本

本台账的证据来自两个同引擎样本，如实记录以便区分「格式事实」与「单样本观测」：

- onishare 版
  - 脚本：`script_onishare_dl.csx`，10,721,056 字节
    SHA-256 `66727cba9d6a3fc86dceabfcf08fde92fce4d1f04635d2b13148a7789c51e8ee`
  - 封包：`data12.noa`，38,576,750 字节
- Time 版（§0.3 跨样本验证加入）
  - 脚本：`script_time.csx`，17,541,632 字节
    SHA-256 `d6ec151b0f089573a90d022ba578f750ff77a6ad97b68daa052f130fa32e7c6f`
- 容器签名：`Entis\x1A` + `Cotopha Image file`（脚本）/ `ERISA-Archive file`（封包）

## 证据台账

### EV_CONTAINER — 顶层记录布局

- **等级**：observed
- **依据**：0x40 字节文件头之后是一串记录，每条为 8 字节 ASCII 标签 + 小端 `u64` 长度。
- **交叉验证**：`header` 到 `impnativ` 各段边界互不重叠；脚本尾部剩余 26 字节作为 `R_TRAILER` 原样保留。
- **规则**：每段视为半开区间，各自保留源 SHA-256。

### EV_CONSTSTR — 常量字符串表与引用连接

- **等级**：observed
- **布局**：`u32 数量`；随后重复 `u32 UTF-16 码元数` + UTF-16LE 字节 + `u32 站点数` + `站点数 × u32 image 偏移`。
- **交叉验证**：解析 `conststr` 段零字节剩余；每个声明的 `image_offset` 处的小端 `u32` 恰好等于该记录的序号（48,563 条记录、151,496 个站点全部命中）。
- **结论**：所有 `JoinSite` 都基于容器自己声明并经独立验证的偏移，不依赖对二进制做文本扫描。

### EV_FUNCINFO — 函数边界

- **等级**：observed
- **布局**：`u32 数量`；重复 `flags:u32`、`image_offset:u32`、`size:u32`、`reserved:u32`、UTF-16LE 名称，再跳过 `reserved` 字节。
- **规则**：`size` 为有限值时即该函数的精确解码边界；`size=0xFFFFFFFF` 不作指令流解码，按不透明 image 数据保留。

### EV_REFERENCE_DECODER — VM 指令布局

- **等级**：derived / 参考实现
- **来源**：`crskycode/EntisGLS_Tools` 的 `CSXToolPlus/ECSExecutionImageDisassembler.cs`；其 v2/v3 读取逻辑与本样本的内联字面量形式一致（`0x80000000` 后跟 `conststr` 索引）。
- **交叉验证**：每条指令都受所属有限 `funcinfo` 区间约束；解码失败时记为 tier 受阻区域，不猜测后继续。

### EV_CALL_SLOTS — 调用参数槽位与文本角色

- **等级**：derived
- **依据**：逐形态统计 `WitchWizard::OutMsg` 的字符串参数，确认签名为 `OutMsg(name, msg, voice_id...)`。
  实测参数个数分布：2 参数 17,019 次（槽 0 为空 10,798 次、为人名 6,221 次）、3 参数 12,996 次、
  4/5/6 参数共 29 次（多角色同时发声，槽 2 起每人一个语音 ID）。
- **反例检查**：`MessageWindow::SetNameString` 全样本仅调用一次且传空串（引擎用它清空名字栏），
  因此**不**声明为 name 槽——否则会形成一个永不产出文本的形态声明。
- **附带结论**：30 个演出调用（`DoLayerBS`、`LoadImage`、`PlaySound`、`LayerMotion*` 等）的字符串参数
  全为图层键、`trans="300"` 这类属性串或资源名，按证据声明为 `frozen`。
- **载体**：以上结论全部写入 `profiles/entisgls-cotopha.json`，代码只读取不内置。
  换作品时这些调用名可能不同，改数据档即可。

### EV_CALL_SLOTS_TIME — Time 版调用形态（跨样本验证）

- **等级**：derived
- **样本**：`script_time.csx`，17,541,632 字节
  SHA-256 `d6ec151b0f089573a90d022ba578f750ff77a6ad97b68daa052f130fa32e7c6f`（与 onishare 同引擎另一作品）。
- **形态差异（同引擎 L1 参数级 + 少量 L2）**：
  `WitchWizard::OutMsg` 两种签名语料均在，argc=2 计 46,030 次、argc=3 计 41,784 次，
  槽 2 起同为 `vf_*` 语音 ID；onishare 的 `OutMsg` 槽语义直接复用，无需改动。
- **新增封存调用（frozen）**：Time 版剧本偏重立绘/动画演出，出现 25 个 onishare 未声明或仅个位
  出现的调用，逐槽内容证据如下：
  - `WitchWizard::SetFaceImage`（33,114 次）→ `bs_tow002a00f` 类立绘键；
  - `WitchWizard::ChangeBustshot`（17,032 次）/ `MoveBustshot`（1,542 次）/ `AddBustshotEmotion`（13,776 次）
    → `bs_*m` 立绘帧与 `emotion_`/`EmotionProperty_*` 属性；
  - `WitchWizard::SetBSVirtualAnimation` / `SetBSVirtualCurveAnimation` / `SetBSVirtualWalkAnimation` /
    `GetSafeBSPosition3D` → `bs_tow` 等骨架键；
  - `WitchWizard::AddScriptMemoryPoint`（78 次）→ `ev_u002` 场景存档点；`AddScriptPickupPoint`（14 次）→
    `06_tales_00` + 标签 `スタート@06_tales_00`；
  - `WitchWizard::AdjustLayerCenter` / `LayerSetPosition` / `LayerSetZoom` / `LayerSetAngle` /
    `LayerSetTransparency` / `LayerApplyParameter` → `黒`、`背景`、`黒帯上/下`、`演出用背景` 等**图层键**；
  - `MakeRandom`、`effectEyeCatch`、`effectDateEyeCatch`、`ScreenManager::LoadImage`、
    `SoundManager::PlaySound`、`ComplexImageManager::LoadImageInfo`、`ComplexLayer::AddMotionMove`、
    `MessageWindow::SetFaceImage`、`UITitle::PlayBGM`、`SelectMenu::MakeMenuSprite`、
    `Suspend`、`AlbumViewMenuPopup::IsEnabled`、`Config::PlaySystemSE` → 资源名 / 属性串 / UI ID。
  以上全部按 `rest=null` 声明为 frozen，与 onishare 既有 30 个演出调用的处理一致。
- **回归**：新增声明后 onishare 的 `msg/name/choice` 与全部 122,292 条产出数完全不变，
  `texts/` 的 ○ 原文锚行逐字符一致（隔离出一个已被译者改过的 ● 行，不属工具产物差异）。

### EV_NO_CONSUMER_STREAMS — 非调用流字符串非正交流

- **等级**：derived
- **依据**：`script_time.csx` 中 19,738 个字符串引用站点不被任何
  `CALL/EX_CALL/CALL_MEMBER/CALL_NATIVE_MEMBER/CALL_NATIVE_FUNCTION` 消费，全样本无一例
  成为对话——因为 msg/name/choice 的信箱 `WitchWizard::OutMsg`/`ShowMessage`/`AddMenuItem`
  全部通过调用点注入。无消费站点按后继指令统计为：
  `ELEMENT_INDIRECT` 18,634（哈希/表键，如 `ルート判定フラグ`、`サクラカウンタ`）、
  `STORE` 734、`COMPARE` 264、`OPERATE` 163、`SWAP` 23 等，值为属性名（`xpos`、`trans`、
  `mask_u`）、格式化/比较串（`\r;`、`.bmp`）或表键，均属不可翻译资源。
- **交叉验证**：onishare 同规则命中 5,206 个站点，交叉内容一致；跨样本无 JPN 台词内容泄漏。
- **实现**：`disassembler.py build_texts` 将无消费站点固定为 `tag_source=structural` +
  `translate_policy=frozen`，计数以 `no_consumer_entries` 显式暴露在 `extract_report.json`，
  不并入 unresolved（§0.1 要求把「尚未理解」与「已证明非文本」分开）。
- **约束**：该规则成立的前提是「对话只能由已证明的调用槽注入」，来自本方言的
  `EV_CALL_SLOTS`；不适用于其它引擎的默认回复——换引擎时此规则必须随方言一起重审。

### EV_LENGTH_FIELDS — 脚本内依赖长度的字段

- **等级**：observed
- **依据**：全文件扫描后确认只有三处随 `conststr` 长度变化：
  | 字段 | 位置 | 含义 |
  |---|---|---|
  | 区段长度 | `0x76CDE8` (u64) | `conststr` 段字节数 |
  | 头部总计 | `0x38` (u64) | 各区段末尾减去 0x40 |
  | 尾部自指针 | 尾部 26 字节内 (u32) | 各区段末尾的绝对偏移 |
- **关键前提**：image 中的引用站点存的是 `conststr` **索引**，不是字节偏移，因此字符串变长不会让任何
  引用失效，无需指针重定位。
- **注意**：封包内存储的 csx 没有那 26 字节尾部，所以尾部自指针缺失属正常，只更新头部长度即可。

### EV_NOA_INDEX — 封包索引布局

- **等级**：observed（对照游戏自带打包器 `noa32c.exe` 的实际输出）
- **目录记录**（小端）：
  ```
  u64 size            解码后的载荷长度
  u32 attr            0x01000000 = 普通文件；0x10 = 子目录；0x20/0x40 = 终止符
  u32 encryption      见 EncType
  s64 offset          相对于所属 DirEntry 起始
  u64 reserved        引擎时间戳，须原样保留
  u32 extra_length    随后该长度的字节（attr 无 0x70 位时）
  u32 name_length     随后该长度的字节，含结尾 NUL
  ```
- **实测规则**：
  - 索引 `size` 是磁盘上文件的真实字节数。
  - `filedata` 存储长度对 BSHF 条目为 `ceil(size / 32) * 32 + 4`。
  - 条目按 Windows 枚举顺序排列（大小写不敏感，`_` 排在字母之后）。
  - `0x38` 记录从 64 字节头之后算起的总长度；替换文件后必须更新，否则引擎读不到末尾条目，
    界面报「スクリプトファイルが見つかりません」。

### EV_BSHF — BSHF 加密

- **等级**：observed
- **密钥派生**（`noa32c.exe` sub_415D70）：密码不足 32 字节时补 `0x1B`，其后 `key[i] = key[i%c] + key[i-1]`。
- **置换**（sub_414B50）：每 32 字节一块，由 `key_offset` 决定一张 256 位置换表；编解码共用同一张表，
  只是读取方向相反。`key_offset` 每块 +1 并按密钥长度回绕，因此 32 字节密钥只有 32 种置换。
- **交叉验证**：明密文 popcount 相同（88/88）证明是纯位置换；对 `data12.noa` 全部 110 个条目
  解密再加密，输出与原始存储字节逐字节相同。
- **未决**：每个条目末尾 4 字节由 sub_414FB0 刷出编码器寄存器得到，依赖整个明文的累积状态。
  已排除 CRC32、Adler32、字节和、MD5/SHA 前 4 字节、额外块置换。**引擎会校验这 4 字节**——
  实测把自建封包的这 4 字节换成打包器写的值，游戏即正常启动。因此封包一律交给 `tools/noa32c.exe`。

### EV_KEYS — 封包密钥

- **等级**：observed
- **来源**：`onisharedl.exe` 的 `IDR_COTOMI` 资源（380 字节 @ `0x350738`），Nemesis 压缩的 XML。
  用参考实现编译出的解码器解开后得到游戏自己的配置：
  ```xml
  <archive path="$(CURRENT)\data12.noa" key="20140811VER22"/>
  <archive path="$(CURRENT)\data13.noa" key="20140811VER23"/>
  <archive path="$(CURRENT)\data15.noa" key="20140811VER25"/>
  <archive path="$(CURRENT)\data17.noa" key="20140811VER27"/>
  ```
- **验证**：用 `20140811VER22` 解 `data12.noa`，97 个 `.eri` 全部以 `Entis\x1A` 开头，csx 头部为
  `Entis\x1A…Cotopha Image file`。
- **载体**：写入 `profiles/entisgls-cotopha.json`。**这是作品专属数据，不是格式的一部分**——
  其它作品各有自己的密钥，通常同样存在宿主 exe 的 `IDR_COTOMI` 资源里。界面也支持手填密码。

## 字面量与指令编码

宽字符串字面量有两种形式：内联（`u32 字符数` + UTF-16LE 字节）或内联到常量表：

```text
u32 0x80000000
u32 sid              # conststr 索引
```

`opcodelist.py` 声明了 `0x00..0x15`、`0x17`、`0x18`、`0x1A`、`0x1D`，含以下较新形式：

```text
0x0F ExOperate:        sub=0 ArrayDim: i32 维数, 维数 × i32
0x10 ExUniOperate:     sub=4 StaticCast: 3 × i32; sub=5 DynamicCast: 字面量
0x11 ExCall:           i32 参数个数, u8 对象模式, u8 变量类型, 载荷
0x12 ExReturn:         u8 是否释放栈
0x13 CallMember:       i32 参数个数, i32 类索引, i32 函数索引
0x14 CallNativeMember: i32 参数个数, i32 类索引, i32 函数索引
0x15 Swap:             u8 子码, i32 索引1, i32 索引2
0x1D CallNativeFunction: i32 参数个数, i32 导入原生函数索引
```

## 理解深度申报

- 容器与常量字符串表：**T2**。边界、字符串身份、全部声明的引用站点均已解析。
- 有限且解码成功的 `funcinfo` 区间：**T3**。指令边界已知且有界。
- 与声明的 VM 读取规则矛盾的函数：**T2**，在覆盖证书中记为 `tier_blocked_at`，字节按
  `unknown_opaque_block` 保留。
- 整个工件的最低 tier 为 **T0**——不由有限函数条目覆盖的 image 区间按不透明保留。
  如实申报：产物具备完整字节覆盖与零编辑往返一致，但不声称完成了全 image 的语义反汇编。

`classinf` 段的名称使用需经 `conststr` 解析的名称表形式，本模块尚未实现该读取器；它不影响任何文本
`JoinSite` 的建立，因此作为有界不透明段保留，成员调用以 `class#N::method#M` 的数字标签呈现。

## 能力边界

| 能力 | 状态 |
|---|---|
| 封包解包（含 BSHF 解密，密钥内置） | 可用，`data12.noa` 实测 110/110 |
| 封包打包 | 交由 `tools/noa32c.exe`，游戏实测可正常启动 |
| 脚本文本提取（msg / name / choice） | 可用，onishare 与 time 两样本均通过产出合理性门禁 |
| 脚本零编辑回封 | 逐字节一致（两样本均验证） |
| 脚本变长回封 | 自身校验通过（可重新解析、站点集合同构、新文本确实写入），但装回游戏后仍报找不到脚本，**未通过实机验证** |
| Nemesis 压缩条目 | 解码器未达位精确，读取时明确报错而不返回截断数据；`data11`–`data18` 中不含此类条目 |

## 未做的验证

- `check_sites.py` 门禁在 15 万站点规模下未跑完，未取得结论。
- 9,900 条 `review-required` 文本的调用形态尚未归类，保持 `unresolved`，未擅自贴标签。

## 跨样本验证记录（§0.3）

- 两样本：`script_onishare_dl.csx`（onishare 版）与 `script_time.csx`（Time 版），同引擎
  EntisGLS / Cotopha，形态签名分布不同（OutMsg 的 argc 分布、新增 25 个立绘/动画演出调用）。
- 修复后两侧均通过产出合理性门禁（`check_output_sanity.py` 退出码 0）：
  | 样本 | exported | msg | name | choice | unresolved | no_consumer |
  |---|---|---|---|---|---|---|
  | onishare | 122,292 | 30,044 | 19,246 | 64 | 4,083 | 5,206 |
  | time | 180,902 | 43,983 | 33,273 | 35 | 2,574 | 19,738 |
- 回归：onishare 的 `msg/name/choice` 条数与 122,292 总条数不变，`texts/` 的 ○ 原文锚行逐字符一致；
  两侧零编辑回封均逐字节一致（三种哈希相同），ASM 二次渲染哈希一致（渲染确定性）。
