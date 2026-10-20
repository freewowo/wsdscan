# 故障排查手册

按症状查。每条都是本项目实际踩过的坑。

---

## 连接类

### 点了"检测连接"，报 `timed out`

逐层缩小范围：

```bash
ping 192.168.1.100            # ① 网络通不通
curl -m 5 http://192.168.1.100:3911/DevMgmt/ProductConfigDyn.xml   # ② HTTP 通不通
```

| 结果 | 含义 | 处理 |
| --- | --- | --- |
| ping 不通 | 三层不通 / IP 写错 / 设备离线 | 查 IP，或看设备面板确认 IP |
| ② 也超时 | 3911 被 ACL 挡了 | 联系网管放行目标 IP 的 TCP 3911 |
| ② 有 XML，但 Probe 超时 | UDP 3702 被挡 | **正常**，项目会自动走 HTTP 兜底，稍等即可 |
| 报 `Connection refused` | 端口没监听 | 设备没起 WSD 服务，重新插电/重启打印机 |

**深度睡眠的设备**：Probe 响应可能延迟到 5 秒以上。软件总预算 6 秒，且每个
HTTP 请求失败会自动重试一次。如果一直 timed out，先在打印机面板上点一下唤醒它。

### 报 `HTTP Error 500: Internal Error`

设备侧 SOAP 处理失败。最常见原因是**请求体里带了不认识的值**（比如不存在的 DPI）。
把参数改回默认（300 dpi / 彩色 / A4 / 平板）再试。

### 报 `连接被重置`

设备重启了，或者扫描器刚好被别的客户端占了。稍等 5 秒重试。

---

## 扫描类

### 扫出来一片空白 / 全黑

1. 纸放反了 —— 正面朝下贴玻璃。
2. 扫描区域框住了白边 —— 用"裁剪 → 留边 3%"或自己拉框。
3. 玻璃上有污渍 —— 擦一下。

### 扫出来尺寸不对，远小于预期

**90% 是 DPI 静默降级。** 这两型机器的 DPI 白名单：

* 平板：100 / 300 / 600
* 进纸器：100 / 300

**请求 200 dpi 不报错，会按 75 dpi 输出。** 软件会检测这种不一致
（比对实际像素宽度与 `region_w/1000*dpi`）并提示。改成 100 或 300 即可。

### 扫得特别慢 / 超过 3 分钟没反应

打印机扫描引擎睡了或卡了。**重启打印机**，这是最有效的办法。
另外 600 dpi 彩色 A4 单页确实可能要 1~2 分钟，不是卡住。

### 报 `没有取到图像`

`RetrieveImage` 返回了 fault 或者 IncompleteRead。先用默认参数试；
若仍失败，重启打印机（见下面"扫描引擎卡死"）。

---

## 打印机扫描引擎卡死 ⚠️

**症状**：突然之间连平板单页 75 dpi 都超时，`CreateScanJob` 挂 45 秒。

**成因**：HP 这两型机器的扫描引擎对**连续快速的 create / cancel** 很敏感，
把它挂住了。本项目在调试期反复触发过（我的锅），确认过代码没问题
（换另一台同型号设备立刻正常）。

**处理**：**重启打印机。** 没有软件层的恢复办法。

**规避**：`CreateScanJob` 超时已经从 90 秒压到 45 秒，这样卡住时能更快暴露而不是干等。

---

## 进纸器 / ADF

### 明明放了纸，软件说没有纸

eSCL 的 `AdfState` **在这两型机器上是坏的**，恒定报 Empty。
软件已改为读 HP LEDM（`/DevMgmt/ProductStatusDyn.xml`）的
`scannerAdfLoaded` / `scannerAdfEmpty`。

如果软件报"未检测到纸张"但打印机面板显示"已检测到文档"：
先确认面板真的看到了纸；再重启一次打印机。若仍不一致，
请把下面这行的输出提 issue：

```
curl -s http://<ip>:3911/DevMgmt/ProductStatusDyn.xml
```

### 选了"进纸器"，出来还是平板的尺寸

已确认是设备问题，不是配置问题。详见
[`PROTOCOL.md` §5](PROTOCOL.md#5-进纸器为什么不可用) 和 README 的"已知限制"。
**这台机器的自动进纸只能用面板 + U 盘。**

---

## 裁剪 / 纠偏

### 拖动裁剪框时画面错乱

早期版本确实有过（移动选框时用了上一帧的坐标），已修。
如果还看到，请记录操作步骤提 issue。

### 纠偏后四周出现白边

正常。`rotate_free()` 用 `expand=True`，会补白边保证完整不裁切。
把选框往里收，就能把白边切掉。

### 自动纠偏角度不对

投影法对"文字行清晰、方向一致"的页面效果最好。
如果页面是大幅图片、或者里面本来就有明显斜线装饰，
估算可能跑偏 —— 用手动滑杆 / 方向键覆盖即可（←/→ 每次 0.1°，加 Shift 是 1°）。

---

## 打包 / 运行环境

### exe 被杀毒软件报毒

PyInstaller onefile 的常见误判。它的工作原理就是把解释器和依赖解压到
`%TEMP%` 再运行，看起来像"自解压释放文件"。加白名单即可。
不放心可以跑源码版：`python WsdScanGUI.py`。

### 跑源码报 `UnicodeDecodeError` / 中文乱码

Windows 上如果设了 `PYTHONUTF8=1` 又叠加了 GBK 编码的 `.pth` 文件，import 就会炸。
跑之前清掉环境变量：

```bash
unset PYTHONPATH PYTHONUTF8 PYTHONIOENCODING
```

（项目在 meson/Git Bash 下已验证；PowerShell 下用 `$env:PYTHONUTF8=""`。）

### exe 里图标没变 / 任务栏还是默认图标

`resource_path()` 按 `sys._MEIPASS` → 源码目录 → exe 目录的顺序找
`wsdscan.ico` / `wsdscan.png`。如果三个位置都没有，会静默跳过（不报错）。
重新跑 `build.bat` 即可，脚本里带 `--add-data "wsdscan.ico;."`。

### PyInstaller 报 `trash-failed` / 无法删除 dist

exe 自己还在跑。先杀进程再删：

```bash
taskkill //F //IM WsdScan.exe
rm -rf dist build WsdScan.spec
```

---

## 提 issue 时请附上

1. 打印机型号 + 固件版本（EWS 首页有）
2. 本机和打印机的 IP / 掩码，确认是否不同网段
3. `python wsdscan.py --host <ip> --info` 的完整输出
4. `curl -s http://<ip>:3911/DevMgmt/ProductStatusDyn.xml` 的输出
5. 报错时的完整弹窗文字
