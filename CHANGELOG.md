# 更新日志

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [1.0.0] - 2026-10-20

首个可用版本。从"VueScan 扫不到别的网段的打印机"这个问题出发，
自绘了完整协议栈，最终做到跨网段直连扫描。

### 新增

* **跨网段直连** —— 填 IP 即连。把 WS-Discovery 的 Probe 改成定向单播（UDP 3702），
  绕过"组播不出子网"这个根本限制。
* **发现兜底** —— UDP 3702 不通时，走 HP LEDM
  `GET /DevMgmt/ProductConfigDyn.xml` 拿 `<dd:UUID>`，再拼
  `http://<ip>:3911/<UUID>`。两条路并行，先到先用，总预算 6 秒。
* **WS-Transfer / WS-Scan 完整实现** —— `CreateScanJob` → `RetrieveImage`，
  含 MTOM multipart 附件解析，以及 base64 `<wscn:ScanData>` 兜底分支。
* **多页连续扫描** —— 逐页 `扫描下一页`，或一次任务整叠扫。
* **横竖版切换** —— 90° × 4，用 `transpose` 无损转置。
* **选框裁剪** —— 拖拽画框 / 框内拖动 / 8 控制点 / 三分参考线；
  选框存相对坐标，可整套套用到其他页。
* **手动纠偏** —— ±15° 任意角度旋转，滑杆 + 方向键（←/→ 微调 0.1°，Shift 为 1°）。
* **自动纠偏** —— 投影法估算倾斜角，纯 Pillow 实现，不引 numpy。
* **纸张检测** —— HP LEDM 优先读 `scannerAdfLoaded` / `scannerAdfEmpty`。
* **输出格式** —— PDF（多页合并）/ JPG / PNG。
* **中文错误提示** —— `human_error()` 把各类异常翻成可执行的下一步。

### 修复

* **eSCL `AdfState` 恒定报 Empty** —— 实测这两型机器放着纸也报 Empty，
  连续 3 次复现。改为 LEDM 优先，eSCL 只作兜底。
* **裁剪对话框移动选框时尺寸错乱** —— 移动分支用了上一帧的坐标
  （`sel0` 未刷新），已改为取当前框。
* **裁剪"取消"绕过 `WM_DELETE_WINDOW`** —— 主窗口会卡在 busy 状态出不来，
  已统一走 `_cancel()`。
* **裁剪预览固定 860×600** —— 300 dpi A4 根本看不全，改为按屏幕自适应。
* **`CreateScanJob` 阻塞 90 秒** —— 增加了 `get_paper()` 预检，
  没纸时 0.2 秒就拦下来。
* **PyInstaller 产物 29 MB** —— 裁掉 numpy/pandas/matplotlib 等，降到 13.6 MB。

### 已知限制

* M128fp 的进纸器在网络上**无法驱动**（设备侧问题，协议分析见 `docs/PROTOCOL.md` §5）。
* 只支持 `dib`（BMP）格式，本地再转码。
* DPI 有白名单（平板 100/300/600，进纸器 100/300），不在名单里会被**静默降级**。
* HP 扫描引擎对连续快速 create/cancel 敏感，可能卡死；**重启打印机**可恢复。

[1.0.0]: https://github.com/freewowo/wsdscan/releases/tag/v1.0.0
