# 协议详解：WS-Discovery / WS-Transfer / WS-Scan

本文记录本项目逆向 + 实测得到的第一手结论。所有请求 / 响应都经过抓包核对，
不是从规范文档抄的。**单位制和几个坑在文末，请务必读完。**

---

## 0. 端口与端点

| 端口 | 服务 | 用途 |
| --- | --- | --- |
| UDP 3702 | WS-Discovery | 设备发现。默认组播 `239.255.255.250` |
| TCP 3911 | WS-Discovery / WS-Transfer / WS-Scan | HTTP over SOAP |
| TCP 8080 | eSCL (AirScan) | **只读可用**（Capabilities / Status） |
| TCP 80 | EWS | 固件。扫描配置页是空的，无效 |
| TCP 443 | EWS TLS | 未被使用 |
| TCP 445 | SMB | 不开 |

3911 上的路径形如：

```
http://<ip>:3911/<UUID-Service-Description>/ScannerService
http://<ip>:3911/<UUID-Service-Scan>/ScannerService
```

UUID 来自 `/DevMgmt/ProductConfigDyn.xml` 里的 `<dd:UUID>`。
这是本项目"发现兜底"的基础：UDP 3702 被防火墙挡掉时，直接 GET 这个 XML 拿 UUID，
再拼 `http://<ip>:3911/<uuid>`。

---

## 1. WS-Discovery：跨网段的关键

规范里的 Probe 是组播。组播不出子网 —— **这就是 VueScan / Windows 传真和扫描
扫不到另一个网段打印机的根因。**

改成**定向单播**发给具体 IP 即可：

```http
POST / HTTP/1.1
Host: 192.168.1.100:3702
Content-Type: application/soap+xml

<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:d="http://schemas.xmlsoap.org/ws/2006/02/devprof"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
  <s:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:...</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </s:Header>
  <s:Body>
    <d:Probe>
      <d:Types>dn:NetworkScanner</d:Types>
    </d:Probe>
  </s:Body>
</s:Envelope>
```

**Sponge 差异（Windows 侧）**：Windows 发 Probe 时 `To` 写 Multicast 地址；
定向发给单台设备时用上面的匿名角色 URI，否则设备不回。

响应 UDP 包里的 `<wsd:XAddrs>` 就是扫描服务端点。

### 设备休眠时的坑

深度睡眠的设备不会立刻回 Probe。项目里的 `discover()` 会**并行**发 UDP Probe 和
HTTP 探测，取先回来的那个，总预算 6 秒；并且每个 HTTP 请求失败后自动重试一次。

---

## 2. WS-Transfer：拿元数据 + 枚举服务

```http
POST / HTTP/1.1
Host: 192.168.1.100:3911
Content-Type: application/soap+xml

<s:Envelope ...>
  <s:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
    <wsa:MessageID>...</wsa:MessageID>
    <wsa:To>http://192.168.1.100:3911/<UUID>/ScannerService</wsa:To>
  </s:Header>
  <s:Body><wdp:Get xmlns:wdp="http://schemas.xmlsoap.org/ws/2006/02/devprof"/></s:Body>
</s:Envelope>
```

返回里能拿到 `<wdp:ThisDevice><wdp:FriendlyName>`（型号）、
`<wdp:SerialNumber>`，以及一堆 `<wdp:Hosted>` 服务引用。
本项目只关心 `...:NetworkScan` 类型的服务端点。

---

## 3. WS-Scan：建任务、取图

命名空间：

```xml
xmlns:wscn="http://schemas.microsoft.com/windows/2006/08/wdp/scan"
xmlns:wscn-doc-fmt="http://schemas.microsoft.com/windows/2006/08/wdp/scan/document-format"
```

### 3.1 CreateScanJob

```xml
<wscn:CreateScanJob>
  <wscn:ScanTicket>
    <wscn:JobDescription>
      <wscn:JobName>Scan 1</wscn:JobName>
      <wscn:JobOriginatingUserName>wsdscan</wscn:JobOriginatingUserName>
    </wscn:JobDescription>
    <wscn:DocumentParameters>
      <wscn:Format>dib</wscn:Format>          <!-- 必须 dib！ -->
      <wscn:InputSource>Platen</wscn:InputSource>
      <wscn:ContentType>Auto</wscn:ContentType>
      <wscn:Compression>None</wscn:Compression>
      <wscn:ScalingWidth>100</wscn:ScalingWidth>
      <wscn:ScalingHeight>100</wscn:ScalingHeight>
      <wscn:InputSize>
        <wscn:InputMediaSize>ISO_A4</wscn:InputMediaSize>
        <!-- 或自定：<wscn:MediaSizeWidth>8270</wscn:MediaSizeWidth>
                 <wscn:MediaSizeHeight>11690</wscn:MediaSizeHeight>  -->
      </wscn:InputSize>
      <wscn:ColorProcessing>RGB24</wscn:ColorProcessing>
      <wscn:Resolution>
        <wscn:Width>300</wscn:Width>          <!-- 1/1000 inch 记 -->
        <wscn:Height>300</wscn:Height>
      </wscn:Resolution>
    </wscn:DocumentParameters>
  </wscn:ScanTicket>
  <wscn:ScanIdentifier>...</wscn:ScanIdentifier>
</wscn:CreateScanJob>
```

- `Format` 只认 `dib`（BMP）。写 png / jpeg / tiff → `ClientErrorDocumentFormatNotSupported`。
- `InputSource`：`Platen` / `Feeder` / `ADF`。**M128fp 上 `Feeder` 被接受但忽略**，见 §5。
- `Resolution` 单位是 **1/1000 英寸**，所以 300 = 0.3 inch = 300 dpi。

### 3.2 RetrieveImage

```xml
<wscn:RetrieveImage>
  <wscn:JobId>...</wscn:JobId>
  <wscn:DocumentDescription>
    <wscn:DocumentName>scan_1</wscn:DocumentName>
  </wscn:DocumentDescription>
  <wscn:JobToken>...</wscn:JobToken>
</wscn:RetrieveImage>
```

响应 `Content-Type: multipart/related`，第一个 part 是 SOAP + 附件结构，
第二部分是 binary 图像数据。本项目用 Python `email` 模块解析（比手写边界拆分稳）。
少数设备会把数据 base64 塞进 `<wscn:ScanData>`，这种情况有 fallback 分支。

---

## 4. 单位制巨坑

两套单位并存，差 3 倍：

| 协议 | 单位 | A4 数值 | 8.5 inch 数值 |
| --- | --- | --- | --- |
| **WSD** (`CreateScanJob`) | **1/1000 英寸** | 8270 × 11690 | 8500 × 11000 |
| **eSCL** (`ScannerCapabilities`) | **1/300 英寸** | — | 2550 |

混用会得到 3 倍尺寸错误。代码里 `SIZE_MAP = {"A4": (8270, 11690), ...}` 就是 WSD 制。

**自检方法**：请求 W=8500（8.5 in）@ 100 dpi，出来的图宽应为 850 px 左右。
实测若拿到 **640 × 866**：宽 8.53 in（对了）、高 11.55 in —— 高度被**夹到平板的 12 英寸上限**，
而不是你请求的 14 in。这就证明了设备走的是平板而不是进纸器（§5）。

---

## 5. 进纸器：为什么不可用

M128fp 在 eSCL 里 advertises `<scc:Adf>` 和 `<FeederCapacity>35</FeederCapacity>`，
看着完全支持。四条路全试过：

| 路径 | 结果 |
| --- | --- |
| WSD `InputSource=Feeder` | 接受，**无效果**，实际仍扫平板 |
| eSCL `POST /eSCL/ScanJobs` | **404** |
| HP LEDM `/Scan/*` | **404** |
| EWS 扫描配置页 | 页面存在，选项全空 |
| SMB 推送 | 445 端口不开 |

**判定方法**（不依赖纸的内容，纯几何证明）：请求 8.5 × 14 in @ 100 dpi。
- 若走平板 → 高度被夹到 12 in → 866 px（实测就是这个）
- 若走进纸器 → 高度应为 14 in → 1400 px

拿到 866，石锤。

**结论**：这台机器的 ADF 只能走面板 + U 盘。这不是本项目的缺陷，是设备本身
就没把 ADF 暴露到网络接口上。

---

## 6. 纸张检测：eSCL 的 `AdfState` 是假的

eSCL `/eSCL/ScannerStatus` 里的：

```xml
<scan:AdfState>ScannerAdfEmpty</scan:AdfState>
```

**在 M126nw 和 M128fp 上都恒定返回 Empty**，哪怕纸已经放进去、打印机屏幕
都显示"已检测到文档"了。连续实测 3 次都是这个结果。

真正可靠的来源是 **HP LEDM**：

```
GET http://<ip>:3911/DevMgmt/ProductStatusDyn.xml
```

```xml
<pscat:StatusCategory>scannerAdfLoaded</pscat:StatusCategory>
<!-- 或 scannerAdfEmpty -->
```

所以 `get_paper()` 实现成 **LEDM 优先，eSCL 兜底**：

1. LEDM 读到 `scannerAdfLoaded` → `Loaded`
2. LEDM 读到 `scannerAdfEmpty` → `Empty`
3. LEDM 能读但没有 ADF 相关状态 → `None`（不代表出错）
4. LEDM 失败才退回去看 eSCL 的（坏的）`AdfState`

顺带：`/DevMgmt/ProductConfigDyn.xml` 里的 `<dd:UUID>` 可用于 §0 的发现兜底。

---

## 7. eSCL：只读能用，写入不行

能用（两型机器都通）：

```
GET /eSCL/ScannerCapabilities    → ADF / 双面 / DPI 列表 / 最大尺寸
GET /eSCL/ScannerStatus          → 状态（但 AdfState 假，见 §6）
GET /eSCL/ScannerStatus.json
```

不能用：

```
POST /eSCL/ScanJobs              → 404
```

有意思的是返回 404 而不是 403，说明这两个型号**没编译进 eSCL 扫描服务**，
只是 vendor 页面挂了两个只读 XML。所有 eSCL 相关的代码都必须按只读处理。

---

## 8. 为什么不做自动搜索整个网段

技术上可以（ICMP sweep + 定向 Probe），但：
* 在 /16 这种大网段里会很吵，且容易触发对方安全告警；
* 打印机经常在睡眠，扫一遍要几十秒；
* 手填 IP 反而更准。

所以默认只搜本 C 段（/24），并且这是一个可选项。
