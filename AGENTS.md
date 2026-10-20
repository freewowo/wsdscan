# 项目速查（给 AI 助手与新贡献者）

先读这份再动代码。**尤其是"容易踩的坑"一节。**

---

## 这是什么

一个跨网段网络扫描工具。核心价值：把 WS-Discovery 的 Probe 从组播改成
**定向单播**，从而穿过三层网关，直接按 IP 连到扫描仪。

* `WsdScanGUI.py` —— 图形界面（tkinter），主交付物
* `wsdscan.py` —— 命令行版，无 GUI 依赖，适合脚本和排查
* `docs/PROTOCOL.md` —— 协议细节与逆向结论。**改协议相关代码前必读**

## 支持什么设备

* HP LaserJet Pro MFP **M126nw / M126a / M128fp**（实测）
* 理论上任何暴露 WSD 扫描服务（TCP 3911）的设备，但只测过上面三种

## 硬件与固件层面的已知限制（不是代码问题，别去"修"）

1. **M128fp 的进纸器无法通过网络驱动。** 四条路全试过都死：
   WSD `InputSource=Feeder` 被接受但忽略、eSCL `POST /ScanJobs` 404、
   LEDM `/Scan/*` 404、EWS 没有扫描设置页。**证据**：请求 8.5×14in @100dpi，
   得到 640×866px —— 高度被夹到平板 12in 上限，说明走的是平板。
   → 不要试图"修好"它，代码里已经如实提示用户了。
2. **只支持 `dib`（BMP）格式。** png/jpeg/tiff 一律
   `ClientErrorDocumentFormatNotSupported`。所以**永远请求 dib，本地转码**。
3. **eSCL 的 `AdfState` 是假的。** 放着纸也恒定报 `ScannerAdfEmpty`。
   纸张检测**必须**用 HP LEDM
   `GET /DevMgmt/ProductStatusDyn.xml` 的 `scannerAdfLoaded` / `scannerAdfEmpty`。
4. **DPI 有白名单且静默降级。** 平板 100/300/600，进纸器 100/300。
   请求 200 不报错，按 75 输出。检测办法：比对实际像素宽与 `region_w/1000*dpi`。
5. **HP 扫描引擎容易卡死**，连平板都超时。**只能重启打印机。**
   `CreateScanJob` 超时因此压到 45 秒。

## 单位制（必读，错一次就是 3 倍误差）

| 协议 | 单位 | A4 |
| --- | --- | --- |
| WSD（`CreateScanJob`） | **1/1000 英寸** | 8270 × 11690 |
| eSCL（`ScannerCapabilities`） | **1/300 英寸** | 8.5in = 2550 |

代码里 `SIZE_MAP = {"A4": (8270, 11690)}` 是 WSD 制，别混。

## 代码结构速查

```
wsdscan.py          CLI
WsdScanGUI.py       GUI
  ├─ 协议层
  │   discover_udp / discover_ledm / discover   定向单播 + HTTP 兜底，并行
  │   _soap_req / http_post / _post_retry      SOAP 与自动重试
  │   get_scanner / get_state                   WS-Transfer
  │   start_job / pull_page / cancel_job        WS-Scan
  │   scan_batch / scan_image                   多页
  │   escl_get / get_caps / get_paper           eSCL 只读 + LEDM
  │   human_error                               异常 -> 中文可执行提示
  ├─ 图像层
  │   apply_rotation   90° 整数倍，transpose 无损
  │   rotate_free      任意角度，BICUBIC，expand 补白
  │   estimate_skew    投影法自动纠偏（纯 Pillow，无 numpy）
  │   crop_rel         相对坐标裁剪
  └─ 界面层
      CropDialog      选框 + 纠偏滑杆 + 自动纠偏
      MultiPageDialog 多页管理
      App             主窗口
```

## 资源路径（打包后也要能跑）

`resource_path()` 按 `sys._MEIPASS` → 源码目录 → exe 目录 找 `wsdscan.ico`/`wsdscan.png`。
`build.bat` 用 `--add-data "wsdscan.ico;."` 把它们放进 `_MEIPASS` 根目录。
**新增附带文件必须在 build.bat 里也加一条 `--add-data`**，否则打包后找不到。

## 容易踩的坑

* **别改成全局并行扫全网段。** 只扫本 C 段，且必须是用户主动点的选项。
  扫 /16 又慢又容易触发对方安全告警。
* **兜底链路别改成串行。** `discover()` 必须并行发 UDP Probe 和 HTTP，
  取先到的。串行的话深睡眠设备要等两份超时，体验崩。
* **多页/进纸器批量的结束判定不要依赖 `get_paper()=="Empty"`。**
  设备可能中途把 ADF 状态刷掉。用 fault / IncompleteRead 判结束。
* **GUI 里所有 IO 必须丢工作线程 + `queue.Queue`，UI 线程只画。**
  现有模式：`after(120, self._drain)` 轮询队列。
* **弹给用户的错误必须过 `human_error()`。** 不要把 `URLError` 原文丢出去。
* **CropDialog 的选框存在像素坐标，但回调传出去的是相对坐标 + 角度。**
  所以同一个框能套到不同尺寸的其他页。改这里务必保持这个约定。

## 测试环境

Windows + Git Bash + Python 3.10。注意：

```bash
unset PYTHONPATH PYTHONUTF8 PYTHONIOENCODING
```

否则系统 Python 会因为 GBK 编码的 `.pth` 报 `UnicodeDecodeError`。
控制台中文会乱码，需要可靠输出时**写到 UTF-8 文件再读**。
