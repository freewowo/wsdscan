# WSD Scan

**一个能跨网段扫描的网络扫描工具 —— 直接填 IP 就能用，不依赖 mDNS、不依赖厂商的云。**

Windows 下常见的"扫描不到打印机"，绝大多数不是网络不通，而是**发现协议**走不了三层网关：
`WSD`（WS-Discovery）默认跑在 UDP 3702 的**组播**上，而组播不出子网。
于是 mDNS / SSDP / 各种"自动搜索"在本机 192.168.1.58 面前，对 192.168.1.100 上的打印机一律视而不见。

本项目换个思路：**不搜索，直接问**。把 WS-Discovery 的 Probe 做成**定向单播**发给目标 IP，只要路由可达（能 ping 通）就能跨网段握手。
再顺着 WS-Transfer 拿到扫描服务端点，用 WS-Scan 建任务、取图。

> 实测环境：本机 192.168.1.58，打印机分布在 192.168.1.x / 192.168.2.x 两个不同网段。全部可用。

---

## 功能

| 功能 | 说明 |
| --- | --- |
| **跨网段直连** | 填 IP 即连，不组播、不广播，跨 VLAN / 三层网关可用 |
| **搜索本网段** | 可选，用 ICMP + 定向 Probe 扫一遍 C 段，找出所有支持 WSD 的扫描仪 |
| **多台设备管理** | 记住最近用过的 IP，下拉即可切换 |
| **多页连续扫描** | 逐页扫（`扫描下一页`）或一次任务整叠扫（进纸器批量） |
| **横竖版切换** | 90° × 4，用 `transpose` 无损转置，不重采样、不降质 |
| **选框裁剪** | 拖拽画框、框内拖动、8 个控制点缩放、三分构图参考线 |
| **手动纠偏** | 滑杆 / 方向键整页旋转 ±15°，扫描歪了当场掰正 |
| **自动纠偏** | 投影法估算倾斜角（纯 Pillow 实现，不依赖 numpy） |
| **输出格式** | PDF（多页合并）/ JPG / PNG |
| **纸张检测** | 先问打印机"进纸器有没有纸"，没纸立刻拦下来，不白等 90 秒 |
| **中文错误提示** | 每种失败都翻译成"下一步该干什么" |

---

## 快速开始

### 方式一：直接用 exe（推荐）

去 [Releases](https://github.com/freewowo/wsdscan/releases) 下载 `WsdScan.exe`
（约 13.6 MB，单文件、无需安装），双击运行：

1. 在"IP 地址"里填打印机的 IP，例如 `192.168.1.100`，点 **检测连接**。
2. 看到型号和序列号后，设置参数，点 **开始扫描**。

> exe 是 PyInstaller onefile 版，解压在 `%TEMP%` 下运行。被杀毒软件误报属正常现象，属于 PyInstaller 的常见误判。
>
> 不想装 exe 也可以用下面的源码方式。

### 方式二：跑源码

```bash
git clone https://github.com/freewowo/wsdscan.git
cd wsdscan
pip install -r requirements.txt
python WsdScanGUI.py          # 图形界面
python wsdscan.py --help      # 命令行
```

### 方式三：自己打包

```bat
build.bat
```

产物在 `dist\WsdScan.exe`（`dist/` 已在 `.gitignore` 里，不进仓库）。

命令行示例：

```bash
python wsdscan.py --host 192.168.1.100 --info
python wsdscan.py --host 192.168.1.100 --dpi 300 --mode 彩色 \
                   --size A4 --format pdf --out ./scan.pdf
```

---

## 设备兼容性

### 已验证可用

| 型号 | 平板扫描 | 多页 | 纸张检测 | 备注 |
| --- | --- | --- | --- | --- |
| HP LaserJet Pro MFP **M126nw** | ✅ | ✅ | ✅ 有 ADF | 主力机型，最稳 |
| HP LaserJet Pro MFP **M126a** | ✅ | ✅ | — | 无进纸器 |
| HP LaserJet Pro MFP **M128fp** | ✅ | ⚠️ | ✅ | **进纸器无法通过网络驱动**，见下 |

局域网内共发现 4 台 M126nw 系打印机，全部握手成功。

### ⚠️ 已知限制（重要，先读这段再提 issue）

1. **M128fp 的进纸器在网络上不可驱动。**
   它在 eSCL 里 advertised `<scc:Adf>` + `FeederCapacity 35`，看起来完全支持；
   但 `POST /eSCL/ScanJobs` 返回 **404**，WSD 的 `InputSource=Feeder` 会被设备**接受但忽略**（实测无论填什么，出来的都是平板尺寸）。
   LEDM 的 `/Scan/*` 也全 404，EWS 没有扫描设置页，445 端口不开。
   → **结论：这台机器的自动进纸只能走打印机面板 + U 盘。** 软件里已经把这点明确提示出来了，不会骗你。
2. **只支持 `dib`（BMP）格式。** 换 png / jpeg / tiff，设备一律回
   `ClientErrorDocumentFormatNotSupported`。所以一律请求 `dib`，本地再用 Pillow 转码。
3. **DPI 有白名单，且不支持会静默降级。**
   平板：100 / 300 / 600；进纸器：100 / 300。
   请求 200 dpi 不会报错，会**默默按 75 dpi 输出**。软件通过比对实际像素宽度和
   `region_w / 1000 * dpi` 来发现这种情况并提示。
4. **HP 的扫描引擎容易卡死。** 连续快速地 create/cancel 扫描任务，可能把扫描引擎挂住，
   表现为连平板都超时。**重启打印机即可恢复。** 这是硬件/固件问题，不是本项目的 bug；
   如果你复现了，先重启再试。

---

## 它是怎么工作的

完整协议分析见 [`docs/PROTOCOL.md`](docs/PROTOCOL.md)，这里给一张总览：

```
                    ┌──────────────────────────────────────────────┐
   填 IP 192.168.1.100 │ ① WS-Discovery（定向单播 Probe，UDP 3702） │
        ────────────▶ │     跨网段的关键：单播能过网关，组播不能    │
                      └───────────────────────┬────────────────────┘
                                              │ XAddrs
                                              ▼
                      ┌──────────────────────────────────────────────┐
                      │ ② WS-Transfer Get（取设备元数据 / 枚举服务）│
                      │     http://192.168.1.100:3911/<UUID-Service- │
                      │     ScanIdentifier>…                         │
                      └───────────────────────┬──────────────────────┘
                                              │ 扫描服务端点
                                              ▼
                      ┌──────────────────────────────────────────────┐
                      │ ③ WS-Scan                                   │
                      │     CreateScanJob   → JobId + Token         │
                      │     RetrieveImage   → MTOM 附件 / base64     │
                      └───────────────────────┬──────────────────────┘
                                              │ BMP
                      ④ 本地 Pillow：旋转 / 纠偏 / 裁剪 / 转 PDF ▼
```

辅助探测用的旁路：

* **HP LEDM**（`/DevMgmt/ProductStatusDyn.xml`）—— 唯一可靠的"进纸器有没有纸"来源。
  eSCL 的 `AdfState` 在这两型机器上是**假的**：放了纸也永远报 `ScannerAdfEmpty`，
  本项目吃过这个亏，所以改成 LEDM 优先，eSCL 只作兜底。
* **eSCL / AirPrint**（`/eSCL/ScannerCapabilities`）—— 只读，用来列 DPI、判断有没有 ADF、
  判断支不支持双面。用它扫描（POST ScanJobs）在两型机器上都是 404。

---

## 项目结构

```
.
├── README.md                 本文
├── AGENTS.md                 给 AI / 新贡献者的项目速查表
├── CHANGELOG.md              更新日志
├── CONTRIBUTING.md            contribution 指南
├── LICENSE                   MIT
├── requirements.txt
├── build.bat                 打包脚本（生成 dist/WsdScan.exe）
├── wsdscan.py                命令行版（无 GUI 依赖）
├── WsdScanGUI.py             图形界面版（tkinter）
├── wsdscan.ico               应用图标（16~256 多尺寸）
├── wsdscan.png               图标 PNG 版（256×256）
├── docs/
│   ├── PROTOCOL.md           WS-Discovery / WS-Transfer / WS-Scan 协议细节与踩坑
│   └── TROUBLESHOOTING.md    故障排查手册
└── tools/
    └── make_icon.py          图标生成脚本
```

历史遗留文件（早期排查用，留着有用）：`PrinterCheck.ps1`、`scan.bat`。

---

## 打包

```bat
build.bat
```

产物是 `dist/WsdScan.exe`，单文件，含图标。内部做了模块裁剪（exclude 掉 numpy /
pandas / matplotlib 等），最终约 13.6 MB；不裁的话是 29 MB。

---

## 常见问题

**Q：点了"检测连接"提示 timed out / 连不上？**
A：先 `ping <IP>`。ping 不通说明网络不通，和本软件无关。ping 通但连不上，看
[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) 里"定向 Probe 失败"一节。

**Q：扫出来是空白页 / 全黑？**
A：99% 是玻璃上放了纸但扫描区域选错，或者纸放反了。先试"平板 + 全页"。

**Q：扫描很慢？**
A：300 dpi 彩色 A4 单页通常 10~40 秒。600 dpi 会翻倍。如果超过 3 分钟，
大概率是打印机扫描引擎睡了或卡了，重启打印机。

**Q：能支持 SMB / 扫描到网络文件夹吗？**
A：目前只走 WSD 协议推图到本机。扫描到 SMB 共享是另一套（设备主动 push），不在范围内。

---

## 开源许可

MIT，见 [LICENSE](LICENSE)。欢迎 PR。
