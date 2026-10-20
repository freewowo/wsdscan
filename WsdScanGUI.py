#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSD Scan —— 跨网段网络扫描工具（图形界面）

特点：
  * 直接填 IP 即可连接扫描仪，不依赖 mDNS / 广播，可跨网段
  * 支持多台扫描仪，记住常用 IP
  * 依赖极少：Python 标准库 + 可选 Pillow（转 PDF/JPG/PNG 用）

原理：WS-Discovery 定向单播 -> WS-Transfer 取扫描服务 -> WS-Scan 建任务取图
"""

import base64
import datetime
import email
import http.client
import json
import math
import os
import queue
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "WSD Scan"
VERSION = "1.0.0"
WS_SCAN_NS = "http://schemas.microsoft.com/windows/2006/08/wdp/scan"
ACT = WS_SCAN_NS + "/"
DISCOVERY_PORT = 3702

COLOR_MAP = {"彩色": "RGB24", "灰度": "Grayscale8", "黑白": "BlackAndWhite1"}
SIZE_MAP = {"A4": (8270, 11690), "Letter": (8500, 11000)}
DPI_CHOICES = ["75", "100", "150", "300", "600"]

# 旋转角度按"顺时针"记，本地用 Pillow 无损转置
ROT_CHOICES = {"不旋转": 0, "90° 顺时针": 90, "90° 逆时针": -90, "180°": 180}

SRC_PLATEN = "平板"
SRC_FEEDER = "进纸器"


# ----------------------------------------------------------------- 配置存取
def resource_path(name):
    """取打包后 / 源码运行时都能找到的附带资源路径（PyInstaller onefile 解包到 _MEIPASS）"""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(base, name)
    if os.path.exists(p):
        return p
    # 源码目录 / exe 同级目录兜底
    p2 = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), name)
    return p2 if os.path.exists(p2) else p


def apply_icon(win):
    """给窗口 + 任务栏设置图标；任何一步失败都静默跳过（不影响主流程）"""
    ico = resource_path("wsdscan.ico")
    try:
        if os.path.exists(ico):
            win.iconbitmap(default=ico)
    except Exception:
        pass
    # Windows 任务栏分组图标：iconphoto 优先级更高，用 png 兜底
    try:
        png = resource_path("wsdscan.png")
        if os.path.exists(png):
            img = tk.PhotoImage(file=png)
            win.iconphoto(True, img)
            win._icon_img = img          # 防止被 GC
    except Exception:
        pass


def config_path():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "WsdScan")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        d = os.path.dirname(os.path.abspath(sys.argv[0]))
    return os.path.join(d, "config.json")


def load_config():
    try:
        with open(config_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ------------------------------------------------------------------- 协议层
def discover_udp(host, timeout=2.5):
    """单次定向 WS-Discovery。超时抛 socket.timeout。"""
    probe = f'''<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
<soap:Header>
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
<wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>
</soap:Header>
<soap:Body><wsd:Probe/></soap:Body>
</soap:Envelope>'''.encode("utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(probe, (host, DISCOVERY_PORT))
        raw, _ = s.recvfrom(65535)
    finally:
        s.close()

    txt = raw.decode("utf-8", "replace")
    if "ScanDeviceType" not in txt:
        raise RuntimeError("该地址的设备不是扫描设备（未声明 ScanDeviceType）")
    m = re.search(r"<[^>]*XAddrs[^>]*>([^<]+)<", txt)
    if not m:
        raise RuntimeError("设备未返回 XAddrs（可能禁用了 Web 服务）")
    return m.group(1).split()[0]


def discover_ledm(host, timeout=4):
    """兜底：UDP 3702 被拦时，从打印机 EWS 读 UUID 自行拼出 WSD 端点。"""
    for suffix in ("", ":8080"):
        url = f"http://{host}{suffix}/DevMgmt/ProductConfigDyn.xml"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                txt = r.read().decode("utf-8", "replace")
        except Exception:
            continue
        m = re.search(r"<dd:UUID>([0-9a-fA-F\-]{36})</dd:UUID>", txt)
        if m:
            return f"http://{host}:3911/{m.group(1)}"
    return None


def discover(host, timeout=2.5, total_wait=6.0):
    """并行跑「UDP 定向发现」和「EWS UUID 兜底」，谁先成功用谁。"""
    box = {}
    errs = []

    def _udp():
        try:
            r = discover_udp(host, timeout)
            if r:
                box.setdefault("udp", r)
        except Exception as e:
            errs.append(f"UDP 3702：{e}")

    def _ledm():
        try:
            r = discover_ledm(host)
            if r:
                box.setdefault("ledm", r)
        except Exception as e:
            errs.append(f"EWS：{e}")

    ths = [threading.Thread(target=_udp, daemon=True),
           threading.Thread(target=_ledm, daemon=True)]
    for t in ths:
        t.start()
    deadline = time.time() + total_wait
    while time.time() < deadline:
        if box.get("udp") or box.get("ledm"):
            break
        if not any(t.is_alive() for t in ths):
            break
        time.sleep(0.05)

    got = box.get("udp") or box.get("ledm")
    if got:
        return got

    # 失败时快速探一下 TCP，好判断到底是"网络不通"还是"协议被拦"
    tcp = {}
    for port in (80, 3911):
        try:
            c = socket.create_connection((host, port), timeout=2)
            c.close()
            tcp[port] = True
        except Exception:
            tcp[port] = False

    if not any(tcp.values()):
        raise RuntimeError(
            f"无法连接 {host}\n\n"
            f"这台电脑到该地址的网络不通：TCP 80 和 3911 都连不上。\n\n"
            f"常见原因：\n"
            f"  · IP 填错，或打印机没开机 / 不在线\n"
            f"  · 打印机换了 IP（DHCP 重新分配）—— 到打印机面板打印网络配置页确认\n"
            f"  · 跨网段但没有路由或 ACL 放行\n"
            f"  · 本机不在该网络中（比如换了台电脑、没连公司网/VPN）"
        )

    raise RuntimeError(
        f"无法连接 {host}\n\n"
        f"网络是通的（TCP 80 {'✓' if tcp.get(80) else '✗'}，3911 {'✓' if tcp.get(3911) else '✗'}），"
        f"但扫描服务没有响应。\n\n"
        f"常见原因：\n"
        f"  · 打印机在深度睡眠 —— 按一下面板按键唤醒后重试\n"
        f"  · 该设备不是扫描设备，或禁用了 Web 服务（WSD）\n"
        f"  · 端口 3911 被本机防火墙/安全软件拦截"
    )


def _is_timeout(e):
    """判断异常是不是"超时"这一类（urllib 会包一层 URLError）。"""
    if isinstance(e, (socket.timeout, TimeoutError)):
        return True
    if isinstance(e, urllib.error.URLError) and isinstance(e.reason, (socket.timeout, TimeoutError)):
        return True
    s = str(e).lower()
    return "timed out" in s or "timeout" in s


def _post_retry(req, timeout, retries=1):
    """发 POST，超时自动重试。打印机深度睡眠时第一次请求常常是用来唤醒它的。"""
    last = None
    for i in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.headers.get("Content-Type", ""), r.read()
        except Exception as e:
            last = e
            if i < retries and _is_timeout(e):
                time.sleep(0.8)
                continue
            raise
    raise last


def _soap_req(url, action, body, extra_ns=""):
    ns = ('xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
          'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
          'xmlns:wscn="' + WS_SCAN_NS + '"' + extra_ns)
    env = (f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope {ns}><soap:Header>'
           f'<wsa:To>{url}</wsa:To><wsa:Action>{action}</wsa:Action>'
           f'<wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>'
           '<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>'
           f'</soap:Header><soap:Body>{body}</soap:Body></soap:Envelope>').encode("utf-8")
    req = urllib.request.Request(url, data=env, method="POST")
    req.add_header("Content-Type", "application/soap+xml; charset=utf-8")
    return req


def http_post(url, action, body, timeout=60, retries=0):
    return _post_retry(_soap_req(url, action, body), timeout, retries)


def human_error(e, host=""):
    """把底层异常翻译成用户能看懂、能动手的中文提示。"""
    if _is_timeout(e):
        return (f"连接 {host} 超时\n\n"
                f"端口是通的，但打印机迟迟不回应扫描协议。\n"
                f"最常见的原因是打印机进入了深度睡眠。\n\n"
                f"请按顺序试：\n"
                f"  1. 到打印机面板按任意键，让屏幕亮起来（唤醒）\n"
                f"  2. 等 3~5 秒，再点一次「检测连接」\n"
                f"  3. 若仍超时，到打印机面板打印一张网络配置页，核对 IP 是否变了\n\n"
                f"（程序已自动重试过一次，仍超时）")
    s = str(e)
    if "Connection refused" in s or "拒绝" in s:
        return (f"连接 {host} 被拒绝\n\n"
                f"该地址上有设备，但没有在监听扫描端口。\n"
                f"可能是 IP 填成了别的设备（比如另一台打印机或路由器），"
                f"请核对打印机面板上的 IP。")
    if "No route to host" in s or "unreachable" in s:
        return f"无法到达 {host}\n\n跨网段路由不通，请检查网关/ACL 是否放行该地址。"
    return s


def get_scanner(xaddr):
    ns = ('xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
          'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
          'xmlns:wxf="http://schemas.xmlsoap.org/ws/2004/09/transfer"')
    env = (f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope {ns}><soap:Header>'
           f'<wsa:To>{xaddr}</wsa:To>'
           '<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>'
           f'<wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>'
           '<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>'
           '</soap:Header><soap:Body/></soap:Envelope>').encode("utf-8")
    req = urllib.request.Request(xaddr, data=env, method="POST")
    req.add_header("Content-Type", "application/soap+xml; charset=utf-8")
    _, raw = _post_retry(req, 25, retries=1)
    txt = raw.decode("utf-8", "replace")

    def pick(tag, default="?"):
        m = re.search(rf"<wdp:{tag}>([^<]+)<", txt)
        return m.group(1) if m else default

    info = {"model": pick("ModelName"), "serial": pick("SerialNumber"),
            "name": pick("FriendlyName"), "scanner": None}
    for blk in re.findall(r"<wdp:Hosted>(.*?)</wdp:Hosted>", txt, re.S):
        if "ScannerServiceType" in blk:
            a = re.search(r"<wsa:Address>([^<]+)<", blk)
            if a:
                info["scanner"] = a.group(1)
                break
    if not info["scanner"]:
        raise RuntimeError("设备未提供扫描服务")
    return info


def get_state(scanner_url):
    body = ("<wscn:GetScannerElementsRequest><wscn:RequestedElements>"
            "<wscn:Name>wscn:ScannerStatus</wscn:Name>"
            "<wscn:Name>wscn:DefaultScanTicket</wscn:Name>"
            "</wscn:RequestedElements></wscn:GetScannerElementsRequest>")
    _, d = http_post(scanner_url, ACT + "GetScannerElements", body, timeout=20, retries=1)
    txt = d.decode("utf-8", "replace")
    st = re.search(r"<wscn:ScannerState>([^<]+)<", txt)
    tk_ = re.search(r"<wscn:DefaultScanTicket>(.*?)</wscn:DefaultScanTicket>", txt, re.S)
    return (st.group(1) if st else "?"), (tk_.group(1) if tk_ else "")


# ------------------------------------------------- 设备能力（走 eSCL，只读）
def escl_get(host, path, timeout=6):
    with urllib.request.urlopen(f"http://{host}{path}", timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _block(xml, tag):
    """取 <scc:Adf>...</scc:Adf> 这类段落（大小写两种写法都兼容）。"""
    m = re.search(rf"<scc:{tag}\b.*?</scc:{tag}>", xml, re.S | re.I)
    return m.group(0) if m else ""


def _resolutions(block):
    return sorted({int(x) for x in re.findall(
        r"<scc:(?:X)?Resolution>(\d+)</scc:(?:X)?Resolution>", block)})


def get_caps(host, timeout=6):
    """读 eSCL 能力。这是唯一可靠的进纸器探测方式（WSD 那条路无法判断）。

    返回 dict；读不到就返回 adf=False 的空能力，不抛异常。
    """
    caps = {"adf": False, "adf_duplex": False, "feeder_capacity": 0,
            "adf_dpi": [], "platen_dpi": [], "model": ""}
    try:
        xml = escl_get(host, "/eSCL/ScannerCapabilities", timeout)
    except Exception:
        return caps

    m = re.search(r"<pwg:MakeAndModel>([^<]+)<", xml)
    if m:
        caps["model"] = m.group(1)

    adf = _block(xml, "Adf")
    platen = _block(xml, "Platen")
    caps["adf"] = bool(adf) and ("InputCaps" in adf)
    caps["adf_duplex"] = "AdfDuplexInputCaps" in adf
    caps["adf_dpi"] = _resolutions(adf)
    caps["platen_dpi"] = _resolutions(platen)

    m = re.search(r"<scc:FeederCapacity>(\d+)<", xml, re.I)
    if m:
        caps["feeder_capacity"] = int(m.group(1))
    elif caps["adf"]:
        caps["feeder_capacity"] = 35
    return caps


def get_paper(host, timeout=6):
    """进纸器里有没有纸。返回 'Loaded' / 'Empty' / None（读不到就别猜）。

    踩过的坑：eSCL 的 <scan:AdfState> 在 HP M128fp 上**永远返回 ScannerAdfEmpty**，
    实测放了纸也不更新，用它判断会把有纸当成没纸，直接拦死。
    真正可靠的是惠普 LEDM 的 /DevMgmt/ProductStatusDyn.xml 里的
    <pscat:StatusCategory>scannerAdfLoaded</pscat:StatusCategory>（无进纸器的机器
    根本不会出现这个分类）。所以 LEDM 优先，eSCL 只当兜底。
    """
    cats = set()
    try:
        xml = escl_get(host, "/DevMgmt/ProductStatusDyn.xml", timeout)
        cats = {c.strip().lower() for c in
                re.findall(r"<pscat:StatusCategory>([^<]+)<", xml, re.I)}
    except Exception:
        pass
    if "scanneradfloaded" in cats:
        return "Loaded"
    if "scanneradfempty" in cats:
        return "Empty"
    if cats:
        return None          # LEDM 能读到但没提进纸器，不当成空

    try:
        s = escl_get(host, "/eSCL/ScannerStatus", timeout)
    except Exception:
        return None
    m = re.search(r"<scan:AdfState>([^<]+)<", s, re.I)
    if not m:
        return None
    v = m.group(1)
    if "Empty" in v:
        return "Empty"
    if "Loaded" in v:
        return "Loaded"
    return v


def build_ticket(tpl, dpi, color, size, source=SRC_PLATEN, images=1, rotation=0):
    t = tpl
    t = re.sub(r"<wscn:Format>[^<]*</wscn:Format>", "<wscn:Format>dib</wscn:Format>", t)
    t = re.sub(r"<wscn:ColorProcessing>[^<]*</wscn:ColorProcessing>",
               f"<wscn:ColorProcessing>{COLOR_MAP[color]}</wscn:ColorProcessing>", t)
    t = re.sub(r"<wscn:Resolution>\s*<wscn:Width>\d+</wscn:Width>\s*"
               r"<wscn:Height>\d+</wscn:Height>\s*</wscn:Resolution>",
               f"<wscn:Resolution><wscn:Width>{dpi}</wscn:Width>"
               f"<wscn:Height>{dpi}</wscn:Height></wscn:Resolution>", t)
    # 进纸源：Platen / Feeder
    src = "Feeder" if source == SRC_FEEDER else "Platen"
    t = re.sub(r"<wscn:InputSource>[^<]*</wscn:InputSource>",
               f"<wscn:InputSource>{src}</wscn:InputSource>", t)
    # 一次任务要取几张（进纸器连续扫描靠它）
    t = re.sub(r"<wscn:ImagesToTransfer>\d+</wscn:ImagesToTransfer>",
               f"<wscn:ImagesToTransfer>{max(1, int(images))}</wscn:ImagesToTransfer>", t)
    # 设备端旋转（这里固定 0，横竖版由本地无损转置完成，结果更可控）
    t = re.sub(r"<wscn:Rotation>\d+</wscn:Rotation>",
               f"<wscn:Rotation>{rotation}</wscn:Rotation>", t)
    if size in SIZE_MAP:
        w, h = SIZE_MAP[size]
        t = re.sub(r"<wscn:InputMediaSize>\s*<wscn:Width>\d+</wscn:Width>\s*"
                   r"<wscn:Height>\d+</wscn:Height>\s*</wscn:InputMediaSize>",
                   f"<wscn:InputMediaSize><wscn:Width>{w}</wscn:Width>"
                   f"<wscn:Height>{h}</wscn:Height></wscn:InputMediaSize>", t)
        t = re.sub(r"<wscn:ScanRegionWidth>\d+</wscn:ScanRegionWidth>",
                   f"<wscn:ScanRegionWidth>{w}</wscn:ScanRegionWidth>", t)
        t = re.sub(r"<wscn:ScanRegionHeight>\d+</wscn:ScanRegionHeight>",
                   f"<wscn:ScanRegionHeight>{h}</wscn:ScanRegionHeight>", t)
    return t


def start_job(host, dpi, color, size, source=SRC_PLATEN, images=1, progress=None):
    """建立扫描任务，返回 job 字典。"""
    p = progress or (lambda m: None)
    p("定位设备…")
    xaddr = discover(host)
    p("读取设备信息…")
    info = get_scanner(xaddr)
    p(f"连接 {info['model']} …")
    state, tpl = get_state(info["scanner"])
    if not tpl:
        raise RuntimeError("读不到扫描参数")
    if state not in ("Idle", "Processing"):
        p(f"设备状态：{state}（仍尝试扫描）")

    # 进纸器空的时候设备会一直等着进纸，不先拦住就会卡到超时
    if source == SRC_FEEDER:
        paper = get_paper(host)
        if paper == "Empty":
            raise RuntimeError(
                "进纸器里没有纸\n\n"
                "设备报告进纸器为空（ScannerAdfEmpty）。请：\n"
                "  · 把文稿放入上方进纸器，导纸板贴紧纸张两侧\n"
                "  · 或把「进纸源」改回「平板」用玻璃板扫描"
            )
        if paper == "Loaded":
            p("进纸器已就绪…")

    ticket = build_ticket(tpl, dpi, color, size, source, images, 0)
    body = ("<wscn:CreateScanJobRequest><wscn:ScanTicket>" + ticket +
            "</wscn:ScanTicket><wscn:DestinationToken>ScanDestination</wscn:DestinationToken>"
            "</wscn:CreateScanJobRequest>")
    try:
        _, d = http_post(info["scanner"], ACT + "CreateScanJob", body, timeout=45)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        sub = re.search(r"<SOAP-ENV:Value>(wscn:[^<]+)</SOAP-ENV:Value>", raw)
        code = sub.group(1) if sub else raw[:200]
        if any(k in code for k in ("NoDocument", "MediaEmpty", "NoImages")):
            raise RuntimeError("进纸器里没有纸\n\n请放好文稿后重试，或把进纸源改回「平板」。")
        raise RuntimeError(f"创建任务失败：{code}")
    except Exception as e:
        if _is_timeout(e):
            hint = ("进纸器模式下常见于：纸张没放好、导纸板没夹紧，或进纸器里其实没有纸。\n"
                    "检查后重试；只想扫玻璃板的话，把进纸源改成「平板」。"
                    if source == SRC_FEEDER else
                    "请唤醒打印机（按一下面板按键）后重试。\n"
                    "若反复出现，请把打印机关机再开一次——它的扫描引擎可能被卡住了。")
            raise RuntimeError(f"设备没有响应扫描请求（已等待 45 秒）\n\n{hint}")
        raise
    txt = d.decode("utf-8", "replace")
    jid = re.search(r"<wscn:JobId>(\d+)</wscn:JobId>", txt)
    tok = re.search(r"<wscn:JobToken>([^<]+)</wscn:JobToken>", txt)
    if not jid or not tok:
        raise RuntimeError("创建任务失败：未返回 JobId")
    rg = re.search(r"<wscn:ScanRegionWidth>(\d+)</wscn:ScanRegionWidth>", ticket)
    return {"svc": info["scanner"], "jid": jid.group(1), "tok": tok.group(1),
            "region_w": int(rg.group(1)) if rg else 0, "model": info["model"]}


def _extract_image(ct, data):
    """从 RetrieveImage 响应里取出图像字节（兼容 MTOM 与 base64 两种封装）。"""
    if ct.startswith("multipart"):
        msg = email.message_from_bytes(b"Content-Type: " + ct.encode() + b"\r\n\r\n" + data)
        for part in msg.walk():
            if (part.get("Content-Type", "")).startswith("image"):
                return part.get_payload(decode=True)
        return None
    m = re.search(rb"<wscn:ScanData>([A-Za-z0-9+/=\s]+)</wscn:ScanData>", data)
    return base64.b64decode(re.sub(rb"\s", b"", m.group(1))) if m else None


def pull_page(job, idx=1, timeout=600):
    """取下一页。没有更多页时返回 None（正常结束，不算错误）。

    设备在"没有下一页"时表现不统一：有的回 SOAP fault，有的直接掐断连接
    （Python 里表现为 IncompleteRead）。两种都按"本批结束"处理。
    """
    rb = (f"<wscn:RetrieveImageRequest><wscn:JobId>{job['jid']}</wscn:JobId>"
          f"<wscn:JobToken>{job['tok']}</wscn:JobToken>"
          f"<wscn:DocumentDescription><wscn:DocumentName>P{idx}</wscn:DocumentName>"
          "</wscn:DocumentDescription></wscn:RetrieveImageRequest>")
    req = _soap_req(job["svc"], ACT + "RetrieveImage", rb)
    try:
        ct, data = _post_retry(req, timeout, 0)
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        v = re.search(r"<SOAP-ENV:Value>([^<]+)</SOAP-ENV:Value>", txt)
        code = v.group(1) if v else ""
        if idx > 1 and any(k in code for k in ("NoImages", "NoDocument", "JobCompleted")):
            return None
        raise RuntimeError(f"取图失败：{code or txt[:200]}")
    except http.client.IncompleteRead:
        return None
    except Exception as e:
        if idx > 1 and (_is_timeout(e) or "Connection" in type(e).__name__):
            return None
        raise
    return _extract_image(ct, data)


def cancel_job(job):
    try:
        http_post(job["svc"], ACT + "CancelJob",
                  f"<wscn:CancelJobRequest><wscn:JobId>{job['jid']}</wscn:JobId></wscn:CancelJobRequest>",
                  timeout=15)
    except Exception:
        pass


def scan_batch(host, dpi, color, size, source=SRC_PLATEN, max_pages=1,
               progress=None, on_page=None, should_stop=None):
    """扫一页或多页。每取到一页回调 on_page(im, 序号)。返回实际页数。"""
    p = progress or (lambda m: None)
    from PIL import Image
    import io

    job = start_job(host, dpi, color, size, source, max_pages, p)
    # 进纸器扫完最后一页后设备可能一直等着下一张纸。设备自己会用"断连"或 fault
    # 告诉客户端没有下一页了（通常很快），这里再叠一层：进纸器已报空就把这一页的
    # 等待上限压短。注意不能因为"报空"就直接停 —— 有些机器会预先把下一张纸卷进
    # 走纸道，此时纸盘已空但仍有页要取，直接停会丢页。
    page_timeout = 600
    n = 0
    try:
        while n < max_pages:
            if should_stop and should_stop():
                break
            tmo = page_timeout
            if source == SRC_FEEDER:
                tmo = 25 if (n > 0 and get_paper(host) == "Empty") else 90
            p("扫描中，请稍候…" if n == 0 else f"正在取第 {n + 1} 页…")
            raw = pull_page(job, n + 1, tmo)
            if not raw:
                break
            im = Image.open(io.BytesIO(raw))
            im.load()
            im = im.convert("RGB")
            dpi_warn(im.size[0], job["region_w"], dpi, p)
            n += 1
            if on_page:
                on_page(im, n)
    finally:
        if n == 0 or source == SRC_FEEDER:
            cancel_job(job)      # 提前收工时把设备上的任务清掉，免得占着设备
    return n


def dpi_warn(width, region_w, dpi, progress):
    """有些设备遇到不支持的 dpi 会静默降级，这里对比实际宽度给出提示。"""
    if not region_w or not width:
        return
    expect = region_w / 1000.0 * dpi
    if expect > 0 and abs(width - expect) / expect > 0.08:
        real = round(width / (region_w / 1000.0))
        progress(f"注意：设备不支持 {dpi}dpi，实际按约 {real}dpi 输出")


# --------------------------------------------------------------- 横竖版 / 裁剪
def apply_rotation(im, cw):
    """按顺时针角度旋转（90 的整数倍，无损转置，不重采样）。"""
    cw = int(cw) % 360
    from PIL import Image
    if cw == 0:
        return im
    if cw == 90:
        return im.transpose(Image.ROTATE_270)
    if cw == 180:
        return im.transpose(Image.ROTATE_180)
    if cw == 270:
        return im.transpose(Image.ROTATE_90)
    return im.rotate(-cw, expand=True)


def crop_rel(im, box):
    """按相对坐标 (l, t, r, b) ∈ [0,1] 裁剪，返回新图。"""
    l, t, r, b = [max(0.0, min(1.0, float(v))) for v in box]
    w, h = im.size
    x0, y0 = int(round(l * w)), int(round(t * h))
    x1, y1 = int(round(r * w)), int(round(b * h))
    x0, x1 = sorted((x0, x1))
    y0, y1 = sorted((y0, y1))
    if x1 - x0 < 2 or y1 - y0 < 2:
        return im
    return im.crop((x0, y0, x1, y1))


def rotate_free(im, cw):
    """任意角度旋转（顺时针为正），自动补白边 —— 扫描纠偏用。"""
    try:
        cw = float(cw)
    except (TypeError, ValueError):
        return im
    cw = cw % 360.0
    if abs(cw) < 1e-6 or abs(cw - 360.0) < 1e-6:
        return im
    from PIL import Image
    try:
        bg = (255, 255, 255) if im.mode == "RGB" else 255
    except Exception:
        bg = 255
    # PIL 的 rotate 逆时针为正；BICUBIC 比默认的 NEAREST 平滑得多
    return im.rotate(-cw, expand=True, resample=Image.BICUBIC, fillcolor=bg)


def estimate_skew(im, lo=-12.0, hi=12.0):
    """投影法估算页面倾斜角（顺时针为正，失败返回 0.0）。

    做法：把页面缩到很小，按候选角度旋转（不扩展、白底），再把每行压成一个
    平均值；文字行与水平方向对齐时，相邻行均值跳变最大，该角度即最优。
    纯 Pillow 实现，不依赖 numpy。
    """
    try:
        from PIL import Image
        w, h = im.size
        if w < 40 or h < 40:
            return 0.0
        s = 300.0 / max(w, h)
        g = im.convert("L")
        if s < 1.0:
            g = g.resize((max(8, int(w * s)), max(8, int(h * s))), Image.BICUBIC)
        gh = g.size[1]

        def score(ang):
            r = g if abs(ang) < 1e-9 else g.rotate(
                -ang, resample=Image.BICUBIC, expand=False, fillcolor=255)
            # 压成 1×gh，就是每一行的平均灰度
            col = r.resize((1, gh), Image.BOX)
            d = list(col.getdata())
            return sum(abs(d[i + 1] - d[i]) for i in range(len(d) - 1))

        # 两段搜索：先粗后细
        best, bs = 0.0, score(0.0)
        a = lo
        while a <= hi + 1e-9:
            v = score(a)
            if v > bs:
                bs, best = v, a
            a += 1.0
        fine = best - 1.0
        end = best + 1.0
        while fine <= end + 1e-9:
            v = score(fine)
            if v > bs:
                bs, best = v, fine
            fine += 0.1
        return round(best, 2)
    except Exception:
        return 0.0


def scan_image(host, dpi, color, size, progress, source=SRC_PLATEN):
    """扫一页，返回 PIL.Image（RGB）。"""
    got = []
    scan_batch(host, dpi, color, size, source, 1, progress, lambda im, i: got.append(im))
    if not got:
        raise RuntimeError("没有取到图像")
    return got[0]


def scan_once(host, dpi, color, size, out_path, fmt, progress,
              source=SRC_PLATEN, rotation=0):
    im = scan_image(host, dpi, color, size, progress, source)
    im = apply_rotation(im, rotation)
    progress("正在保存…")
    if fmt == "PDF":
        im.save(out_path, "PDF", resolution=float(dpi))
    elif fmt == "JPG":
        im.save(out_path, "JPEG", quality=92)
    else:
        im.save(out_path, "PNG")
    return out_path, im.size


def save(raw, out_path, fmt):
    try:
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(raw))
        if fmt == "PDF":
            im.convert("RGB").save(out_path, "PDF", resolution=300.0)
        elif fmt == "JPG":
            im.convert("RGB").save(out_path, "JPEG", quality=90)
        else:
            im.save(out_path, "PNG")
        return out_path, im.size
    except ImportError:
        alt = os.path.splitext(out_path)[0] + ".bmp"
        with open(alt, "wb") as f:
            f.write(raw)
        return alt, None


def save_pages(images, out_path, fmt, dpi=300):
    """多页保存：PDF 合成一个文件，JPG/PNG 按页码分别存。"""
    if fmt == "PDF":
        images[0].save(out_path, "PDF", resolution=float(dpi),
                       save_all=True, append_images=images[1:])
        return [out_path]
    base, ext = os.path.splitext(out_path)
    outs = []
    for i, im in enumerate(images, 1):
        p = f"{base}-{i:02d}{ext}"
        if fmt == "JPG":
            im.save(p, "JPEG", quality=90)
        else:
            im.save(p, "PNG")
        outs.append(p)
    return outs


# ------------------------------------------------------------------- 裁剪窗口
class CropDialog(tk.Toplevel):
    """选框裁剪 + 手动纠偏。

    拖拽画框、框内拖动整体移动、拖八个控制点缩放；滑杆可整页旋转
    ±15°（顺时针为正）来纠正扫描歪斜。

    返回给回调的是：相对坐标 box（相对"已旋转"图片）、是否套用全部页、
    以及旋转角度。三者相对坐标化，所以同一个 box 可以套到尺寸不同的其他页。
    """

    PAD = 12
    MAX_ANGLE = 15.0

    def __init__(self, master, image, on_ok, allow_all=False, title="裁剪",
                 on_cancel=None, angle=0.0):
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.grab_set()
        self.resizable(False, False)

        from PIL import Image

        self.src = image.convert("RGB")
        self.on_ok = on_ok
        self.on_cancel = on_cancel
        self.allow_all = allow_all
        self.var_all = tk.BooleanVar(value=False)

        # 预览用小图：实时旋转整幅 300dpi 大图会卡
        self.angle = 0.0
        w, h = self.src.size
        s = 1000.0 / max(1, max(w, h))
        self.psrc = self.src if s >= 1.0 else self.src.resize(
            (max(1, int(w * s)), max(1, int(h * s))), Image.LANCZOS)
        pw, ph = self.psrc.size

        # 显示比例只算一次：按最大倾斜角的外接框取满屏幕可用区域
        a = math.radians(self.MAX_ANGLE)
        lw = pw * abs(math.cos(a)) + ph * abs(math.sin(a))
        lh = pw * abs(math.sin(a)) + ph * abs(math.cos(a))
        sw, sh = master.winfo_screenwidth(), master.winfo_screenheight()
        maxw = min(900, sw - 140)
        maxh = min(720, sh - 230)
        self.scale = min(maxw / lw, maxh / lh, 1.0)
        self.cw = max(1, int(round(pw * self.scale)))
        self.ch = max(1, int(round(ph * self.scale)))

        # ---- 纠偏控制条
        bar1 = ttk.Frame(self)
        bar1.pack(fill="x", padx=self.PAD, pady=(self.PAD, 4))
        ttk.Label(bar1, text="角度纠偏").pack(side="left")
        self.var_ang = tk.DoubleVar(value=0.0)
        self.sc_ang = ttk.Scale(bar1, from_=-self.MAX_ANGLE, to=self.MAX_ANGLE,
                                length=330, variable=self.var_ang,
                                command=lambda _v: self._on_angle(self.var_ang.get()))
        self.sc_ang.pack(side="left", padx=8)
        self.e_ang = ttk.Entry(bar1, width=6, justify="center")
        self.e_ang.insert(0, "0.0")
        self.e_ang.bind("<Return>", self._entry_angle)
        self.e_ang.bind("<FocusOut>", self._entry_angle)
        self.e_ang.pack(side="left")
        ttk.Label(bar1, text="°").pack(side="left")
        ttk.Button(bar1, text="归零", width=5,
                   command=lambda: self._set_angle(0.0)).pack(side="left", padx=(8, 0))
        self.b_auto = ttk.Button(bar1, text="自动纠偏", command=self.auto_skew)
        self.b_auto.pack(side="left", padx=6)
        ttk.Label(bar1, text="←/→ 微调 0.1°，Shift 为 1°",
                  foreground="#888").pack(side="left", padx=(6, 0))

        # ---- 画布
        self.canvas = tk.Canvas(self, width=self.cw, height=self.ch,
                                highlightthickness=1, highlightbackground="#bbb",
                                cursor="crosshair", background="#e9e9e9")
        self.canvas.pack(padx=self.PAD, pady=4)
        self.canvas.bind("<Button-1>", self._press)
        self.canvas.bind("<B1-Motion>", self._drag)
        self.canvas.bind("<ButtonRelease-1>", self._release)
        self.bind("<Left>", lambda e: self._nudge(-0.1))
        self.bind("<Right>", lambda e: self._nudge(0.1))
        self.bind("<Shift-Left>", lambda e: self._nudge(-1.0))
        self.bind("<Shift-Right>", lambda e: self._nudge(1.0))

        self.sel = [0.0, 0.0, self.cw, self.ch]
        self.sel0 = list(self.sel)
        self.mode = None
        self.anchor = (0, 0)
        self.ox = self.oy = 0.0
        self.rdw = self.cw
        self.rdh = self.ch
        self.pw, self.ph = pw, ph        # 旋转后预览图像素数（0° 时即 psrc 尺寸）

        bar2 = ttk.Frame(self)
        bar2.pack(fill="x", padx=self.PAD)
        self.lbl = ttk.Label(bar2, foreground="#555")
        self.lbl.pack(side="left")

        bot = ttk.Frame(self)
        bot.pack(fill="x", padx=self.PAD, pady=(6, self.PAD))
        if allow_all:
            ttk.Checkbutton(bot, text="应用到所有页（相同角度与比例）",
                            variable=self.var_all).pack(side="left")
        ttk.Button(bot, text="确 定", command=self._ok).pack(side="right", ipadx=18, ipady=3)
        ttk.Button(bot, text="取消", command=self._cancel).pack(side="right", padx=6)
        ttk.Button(bot, text="全选", command=lambda: self._set(0, 0, self.cw, self.ch)
                   ).pack(side="right", padx=6)
        ttk.Button(bot, text="留边 3%", command=self._reset).pack(side="right")

        self._apply_angle(0.0, reset_box=True)
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    # ---------------- 角度
    def _set_angle(self, a):
        self.var_ang.set(a)
        self._apply_angle(a)

    def _entry_angle(self, _e=None):
        try:
            a = float(self.e_ang.get().strip())
        except (TypeError, ValueError):
            a = self.angle
        self._set_angle(max(-self.MAX_ANGLE, min(self.MAX_ANGLE, a)))

    def _on_angle(self, v):
        try:
            a = float(v)
        except (TypeError, ValueError):
            a = 0.0
        self._apply_angle(a)

    def _nudge(self, d):
        self._set_angle(max(-self.MAX_ANGLE, min(self.MAX_ANGLE, self.angle + d)))

    def _apply_angle(self, a, reset_box=False):
        """换角度：保留当前选框的相对坐标，重新渲染背景。"""
        from PIL import Image, ImageTk
        a = max(-self.MAX_ANGLE, min(self.MAX_ANGLE, float(a)))
        rel = None
        if not reset_box and self.rdw > 0 and self.rdh > 0:
            rel = list(self._to_rel())
        self.angle = a
        try:
            self.e_ang.delete(0, "end")
            self.e_ang.insert(0, f"{a:.1f}")
        except Exception:
            pass
        try:
            self.var_ang.set(a)
        except Exception:
            pass

        rot = rotate_free(self.psrc, a)
        rw, rh = rot.size
        dw = max(1, int(round(rw * self.scale)))
        dh = max(1, int(round(rh * self.scale)))
        disp = rot.resize((dw, dh), Image.LANCZOS)
        self._photo = ImageTk.PhotoImage(disp)
        # 画布跟着转后的外接框伸缩，不转时就是原图大小
        self.rdw, self.rdh = dw, dh
        self.pw, self.ph = rw, rh        # 记住"旋转后预览图"的原始像素尺寸
        self.ox = self.oy = 0.0
        self.cw, self.ch = dw, dh
        try:
            self.canvas.configure(width=dw, height=dh)
        except Exception:
            pass
        self.canvas.delete("bg")
        self.canvas.create_image(0, 0, anchor="nw",
                                 image=self._photo, tags="bg")
        self.canvas.tag_lower("bg")

        if reset_box or rel is None:
            self.sel = [self.ox, self.oy, self.ox + dw, self.oy + dh]
        else:
            self.sel = [rel[0] * dw + self.ox, rel[1] * dh + self.oy,
                        rel[2] * dw + self.ox, rel[3] * dh + self.oy]
        self.sel0 = list(self.sel)
        self._redraw()

    def auto_skew(self):
        """投影法自动判断倾斜方向与角度。"""
        try:
            a = estimate_skew(self.psrc)
        except Exception as e:
            self.lbl_hint_set(f"自动纠偏失败：{e}")
            return
        if abs(a) < 0.05:
            self.lbl_hint_set("未检测到明显倾斜（当前为 0°）")
            self._set_angle(0.0)
            return
        self._set_angle(a)
        self.lbl_hint_set(f"已自动纠偏 {a:+.1f}°，不满意可手动微调")

    def lbl_hint_set(self, text):
        try:
            self.lbl.configure(text=text, foreground="#0a6")
        except Exception:
            pass

    # ---------------- 坐标
    def _clamp(self, x, y):
        return (min(max(self.ox, x), self.ox + self.rdw),
                min(max(self.oy, y), self.oy + self.rdh))

    def _norm(self):
        x0, y0, x1, y1 = self.sel
        return min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)

    def _to_rel(self):
        """选框像素坐标 -> 相对"已旋转图片"的相对坐标"""
        x0, y0, x1, y1 = self._norm()
        return ((x0 - self.ox) / self.rdw, (y0 - self.oy) / self.rdh,
                (x1 - self.ox) / self.rdw, (y1 - self.oy) / self.rdh)

    def _handles(self):
        x0, y0, x1, y1 = self._norm()
        mx, my = (x0 + x1) / 2.0, (y0 + y1) / 2.0
        return {"nw": (x0, y0), "n": (mx, y0), "ne": (x1, y0),
                "w": (x0, my), "e": (x1, my),
                "sw": (x0, y1), "s": (mx, y1), "se": (x1, y1)}

    def _set(self, x0, y0, x1, y1):
        self.sel = [x0, y0, x1, y1]
        self._redraw()

    def _reset(self):
        mx, my = self.rdw * 0.03, self.rdh * 0.03
        self._set(self.ox + mx, self.oy + my,
                  self.ox + self.rdw - mx, self.oy + self.rdh - my)

    # ---------------- 交互
    def _press(self, e):
        x, y = self._clamp(e.x, e.y)
        for name, (hx, hy) in self._handles().items():
            if abs(x - hx) <= 8 and abs(y - hy) <= 8:
                self.mode = name
                self.sel0 = list(self._norm())
                return
        x0, y0, x1, y1 = self._norm()
        if x0 <= x <= x1 and y0 <= y <= y1:
            self.mode = "move"
            self.sel0 = [x0, y0, x1, y1]      # 移动要按当前框尺寸算，不能用上次的
            self.anchor = (x - x0, y - y0)
            return
        self.mode = "new"
        self.anchor = (x, y)
        self.sel = [x, y, x, y]

    def _drag(self, e):
        if not self.mode:
            return
        x, y = self._clamp(e.x, e.y)
        if self.mode == "new":
            self.sel = [self.anchor[0], self.anchor[1], x, y]
        elif self.mode == "move":
            w = self.sel0[2] - self.sel0[0]
            h = self.sel0[3] - self.sel0[1]
            nx = min(max(self.ox, x - self.anchor[0]), self.ox + self.rdw - w)
            ny = min(max(self.oy, y - self.anchor[1]), self.oy + self.rdh - h)
            self.sel = [nx, ny, nx + w, ny + h]
        else:
            x0, y0, x1, y1 = self.sel0
            if "n" in self.mode:
                y0 = y
            if "s" in self.mode:
                y1 = y
            if "w" in self.mode:
                x0 = x
            if "e" in self.mode:
                x1 = x
            self.sel = [x0, y0, x1, y1]
        self._redraw()

    def _release(self, _e=None):
        self.mode = None
        x0, y0, x1, y1 = self._norm()
        if x1 - x0 < 6 or y1 - y0 < 6:      # 太小就当误触，恢复全选
            self._set(self.ox, self.oy, self.ox + self.rdw, self.oy + self.rdh)
        self._redraw()

    # ---------------- 绘制
    def _redraw(self):
        self.canvas.delete("ov")
        x0, y0, x1, y1 = self._norm()
        for a, b, c, d in ((self.ox, self.oy, self.ox + self.rdw, y0),
                           (self.ox, y1, self.ox + self.rdw, self.oy + self.rdh),
                           (self.ox, y0, x0, y1),
                           (x1, y0, self.ox + self.rdw, y1)):
            if c > a and d > b:
                self.canvas.create_rectangle(a, b, c, d, fill="#000",
                                             stipple="gray50", outline="", tags="ov")
        self.canvas.create_rectangle(x0, y0, x1, y1, outline="#e33", width=2, tags="ov")
        for i in (1, 2):
            gx = x0 + (x1 - x0) * i / 3.0
            gy = y0 + (y1 - y0) * i / 3.0
            self.canvas.create_line(gx, y0, gx, y1, fill="#e33", dash=(2, 4), tags="ov")
            self.canvas.create_line(x0, gy, x1, gy, fill="#e33", dash=(2, 4), tags="ov")
        for hx, hy in self._handles().values():
            self.canvas.create_rectangle(hx - 4, hy - 4, hx + 4, hy + 4,
                                         fill="#e33", outline="#fff", tags="ov")
        iw = int(round((x1 - x0) / self.scale))
        ih = int(round((y1 - y0) / self.scale))
        self.lbl.configure(
            text=f"选中 {iw} × {ih} 像素　旋转 {self.angle:+.1f}° 后画布 "
                 f"{self.pw} × {self.ph}（原图 {self.src.size[0]} × {self.src.size[1]}）")

    def _ok(self):
        box = list(self._to_rel())
        box = [max(0.0, min(1.0, v)) for v in box]
        apply_all = bool(self.allow_all and self.var_all.get())
        angle = self.angle
        self.destroy()
        self.on_ok(box, apply_all, angle)

    def _cancel(self):
        self.destroy()
        if self.on_cancel:
            self.on_cancel()


# ------------------------------------------------------------------- 多页扫描
class MultiPageDialog(tk.Toplevel):
    """逐页扫描，可排序/删除，最后合并成一个多页 PDF。"""

    def __init__(self, master, host, dpi, color, size, fmt, out_dir,
                 source=SRC_PLATEN, rotation=0, feeder_max=35):
        super().__init__(master)
        self.title("多页连续扫描")
        self.geometry("900x640")
        self.minsize(800, 580)
        self.transient(master)
        self.grab_set()

        self.host, self.dpi, self.color = host, dpi, color
        self.size, self.fmt, self.out_dir = size, fmt, out_dir
        self.source, self.rotation = source, rotation
        self.feeder_max = max(1, int(feeder_max))
        self.pages = []          # 临时 PNG 路径，顺序即页序
        self.sizes = []
        self.tmpdir = tempfile.mkdtemp(prefix="wsdscan_")
        self.busy = False
        self.q = queue.Queue()
        self._imgref = None

        self._build()
        self.after(120, self._drain)
        if self.source == SRC_FEEDER:
            self.lbl_hint.configure(
                text="注意：实测这台设备的网络接口会忽略进纸器设置、仍按平板扫描。"
                     "要用进纸器，请用打印机面板 + U 盘。")
        else:
            self.lbl_hint.configure(text="请把第 1 页放到扫描仪玻璃上，然后点【扫描下一页】")

    # ---------- 布局
    def _build(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=(10, 2))
        ttk.Label(top, foreground="#555",
                  text=f"扫描仪 {self.host}    {self.dpi}dpi / {self.color} / "
                       f"{self.size or '默认纸张'} / {self.fmt} / {self.source}").pack(side="left")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=12, pady=6)

        left = ttk.Frame(body, width=200)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        ttk.Label(left, text="已扫页面").pack(anchor="w", pady=(0, 4))
        box = ttk.Frame(left)
        box.pack(fill="both", expand=True)
        self.lb = tk.Listbox(box, exportselection=False, activestyle="none",
                             selectmode="browse", font=("Microsoft YaHei UI", 9))
        sb = ttk.Scrollbar(box, orient="vertical", command=self.lb.yview)
        self.lb.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.lb.pack(side="left", fill="both", expand=True)
        self.lb.bind("<<ListboxSelect>>", self._on_select)

        self.preview = tk.Label(body, text="（暂无页面）", background="#f7f7f7",
                                foreground="#999", anchor="center")
        self.preview.pack(side="left", fill="both", expand=True, padx=(12, 0))

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=12, pady=(4, 0))
        self.b1 = ttk.Button(btns, text="扫描下一页", command=self.scan_next)
        self.b1.pack(side="left", ipadx=10, ipady=3)
        self.b_batch = ttk.Button(btns, text="批量扫描（进纸器）", command=self.scan_batch_all)
        if self.source == SRC_FEEDER:
            self.b_batch.pack(side="left", padx=(6, 0), ipady=3)
        self.b_crop = ttk.Button(btns, text="裁剪本页", command=self.crop_current)
        self.b_crop.pack(side="left", padx=6)
        self.b_crop_all = ttk.Button(btns, text="裁剪全部", command=self.crop_all)
        self.b_crop_all.pack(side="left")
        self.b2 = ttk.Button(btns, text="删除本页", command=self.del_page)
        self.b2.pack(side="left", padx=6)
        self.b3 = ttk.Button(btns, text="上移", command=lambda: self.move(-1))
        self.b3.pack(side="left")
        self.b4 = ttk.Button(btns, text="下移", command=lambda: self.move(1))
        self.b4.pack(side="left", padx=6)

        self.lbl_hint = ttk.Label(self, text="", foreground="#0a6", wraplength=820)
        self.lbl_hint.pack(fill="x", padx=12, pady=(8, 0))

        bot = ttk.Frame(self)
        bot.pack(fill="x", padx=12, pady=10)
        ttk.Button(bot, text="放弃并关闭", command=self.on_close).pack(side="right")
        self.b5 = ttk.Button(bot, text="保 存", command=self.finish)
        self.b5.pack(side="right", padx=8, ipadx=26, ipady=3)

    # ---------- 队列
    def _drain(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "hint":
                    self.lbl_hint.configure(text=val, foreground="#555")
                elif kind == "page":
                    self._add_page(*val)
                elif kind == "page2":
                    self._add_page(val[0], val[1], unlock=False)
                elif kind == "batchdone":
                    self.busy = False
                    self._lock(False)
                    if val:
                        self.lbl_hint.configure(
                            text=f"批量扫描完成，本次加入 {val} 页，共 {len(self.pages)} 页。"
                                 f"可继续【批量扫描】补扫，或直接【保存】", foreground="#0a6")
                    else:
                        self.lbl_hint.configure(
                            text="进纸器没有送出任何页面 —— 请确认纸张放好、导纸板夹紧后重试",
                            foreground="#b00")
                elif kind == "err":
                    self.busy = False
                    self._lock(False)
                    self.lbl_hint.configure(text="扫描失败", foreground="#b00")
                    messagebox.showerror("扫描失败", val, parent=self)
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _lock(self, busy):
        st = "disabled" if busy else "normal"
        for b in (self.b1, self.b_batch, self.b_crop, self.b_crop_all,
                  self.b2, self.b3, self.b4, self.b5):
            b.configure(state=st)

    # ---------- 扫描
    def _need_pil(self):
        try:
            import PIL  # noqa: F401
            return True
        except ImportError:
            messagebox.showerror("缺少依赖", "多页扫描需要 Pillow：\n\npip install pillow",
                                 parent=self)
            return False

    def scan_next(self):
        if self.busy or not self._need_pil():
            return
        self.busy = True
        self._lock(True)
        n = len(self.pages) + 1
        self.lbl_hint.configure(text=f"正在扫描第 {n} 页…", foreground="#555")

        def work():
            try:
                im = scan_image(self.host, self.dpi, self.color, self.size,
                                lambda m: self.q.put(("hint", m)), self.source)
                im = apply_rotation(im, self.rotation)
                p = os.path.join(self.tmpdir, f"one{n:03d}.png")
                im.save(p, "PNG")
                self.q.put(("page", (p, im.size)))
            except Exception as e:
                self.q.put(("err", human_error(e, self.host)))

        threading.Thread(target=work, daemon=True).start()

    def scan_batch_all(self):
        """进纸器：一次任务把整叠纸全扫完。"""
        if self.busy or not self._need_pil():
            return
        self.busy = True
        self._lock(True)
        self.lbl_hint.configure(text="正在从进纸器批量扫描…", foreground="#555")

        def work():
            try:
                base = len(self.pages)

                def on_page(im, i):
                    im = apply_rotation(im, self.rotation)
                    p = os.path.join(self.tmpdir, f"batch{base + i:03d}.png")
                    im.save(p, "PNG")
                    self.q.put(("page2", (p, im.size)))

                cnt = scan_batch(self.host, self.dpi, self.color, self.size,
                                 self.source, self.feeder_max,
                                 lambda m: self.q.put(("hint", m)), on_page)
                self.q.put(("batchdone", cnt))
            except Exception as e:
                self.q.put(("err", human_error(e, self.host)))

        threading.Thread(target=work, daemon=True).start()

    def _add_page(self, path, size, unlock=True):
        self.pages.append(path)
        self.sizes.append(size)
        if unlock:
            self.busy = False
            self._lock(False)
        self._refresh(select=len(self.pages) - 1)
        if unlock:
            tip = ("换好下一页纸张后，继续点【扫描下一页】"
                   if self.source == SRC_PLATEN else "继续点【扫描下一页】可再放一张")
            self.lbl_hint.configure(
                text=f"第 {len(self.pages)} 页已加入（{size[0]}×{size[1]}）。{tip}",
                foreground="#0a6")

    # ---------- 裁剪
    def crop_current(self):
        c = self.lb.curselection()
        if not c or self.busy:
            return
        self._open_crop(c[0], allow_all=len(self.pages) > 1)

    def crop_all(self):
        if not self.pages or self.busy:
            return
        c = self.lb.curselection()
        self._open_crop(c[0] if c else 0, allow_all=False, force_all=True)

    def _open_crop(self, idx, allow_all=False, force_all=False):
        from PIL import Image
        try:
            im = Image.open(self.pages[idx])
            im.load()
            im = im.convert("RGB")
        except Exception as e:
            messagebox.showerror("读取失败", str(e), parent=self)
            return

        def ok(box, apply_all, angle=0.0):
            targets = list(range(len(self.pages))) if (force_all or apply_all) else [idx]
            moved = 0
            for i in targets:
                try:
                    pim = Image.open(self.pages[i])
                    pim.load()
                    pim = rotate_free(pim.convert("RGB"), angle)   # 先纠偏
                    pim = crop_rel(pim, box)                       # 再按相对坐标裁
                    pim.save(self.pages[i], "PNG")
                    self.sizes[i] = pim.size
                    moved += 1
                except Exception as e:
                    messagebox.showerror("裁剪失败", str(e), parent=self)
                    return
            self._refresh(select=idx)
            tail = f"，旋转 {angle:+.1f}°" if abs(angle) > 1e-6 else ""
            self.lbl_hint.configure(text=f"已处理 {moved} 页（裁剪{tail}）", foreground="#0a6")

        CropDialog(self, im, ok, allow_all=allow_all,
                   title="裁剪全部页" if force_all else "裁剪本页")

    def _refresh(self, select=None):
        self.lb.delete(0, "end")
        for i, s in enumerate(self.sizes, 1):
            self.lb.insert("end", f"第 {i} 页    {s[0]}×{s[1]}")
        if self.pages:
            if select is None:
                select = min(self.lb.curselection()[0] if self.lb.curselection() else 0,
                             len(self.pages) - 1)
            self.lb.selection_clear(0, "end")
            self.lb.selection_set(select)
            self.lb.see(select)
            self._show(select)
        else:
            self.preview.configure(image="", text="（暂无页面）")

    def _on_select(self, _e=None):
        c = self.lb.curselection()
        if c:
            self._show(c[0])

    def _show(self, idx):
        try:
            from PIL import Image, ImageTk
            im = Image.open(self.pages[idx])
            im.load()
            im.thumbnail((470, 520))
            self._imgref = ImageTk.PhotoImage(im)
            self.preview.configure(image=self._imgref, text="")
        except Exception as e:
            self.preview.configure(image="", text=f"预览失败：{e}")

    def del_page(self):
        c = self.lb.curselection()
        if not c:
            return
        i = c[0]
        try:
            os.remove(self.pages[i])
        except OSError:
            pass
        self.pages.pop(i)
        self.sizes.pop(i)
        self._refresh(select=min(i, len(self.pages) - 1) if self.pages else None)
        self.lbl_hint.configure(text=f"已删除，当前共 {len(self.pages)} 页", foreground="#555")

    def move(self, d):
        c = self.lb.curselection()
        if not c:
            return
        i = c[0]
        j = i + d
        if 0 <= j < len(self.pages):
            self.pages[i], self.pages[j] = self.pages[j], self.pages[i]
            self.sizes[i], self.sizes[j] = self.sizes[j], self.sizes[i]
            self._refresh(select=j)

    # ---------- 保存
    def finish(self):
        if self.busy:
            return
        if not self.pages:
            messagebox.showinfo("还没有页面", "请先扫描至少一页。", parent=self)
            return
        ext = {"PDF": ".pdf", "JPG": ".jpg", "PNG": ".png"}[self.fmt]
        stamp = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        p = filedialog.asksaveasfilename(
            parent=self, title="保存多页文件", initialdir=self.out_dir,
            initialfile=f"scan-{stamp}{ext}", defaultextension=ext,
            filetypes=[(self.fmt, "*" + ext)])
        if not p:
            return
        self.lbl_hint.configure(text="正在合成，请稍候…", foreground="#555")
        self.update_idletasks()
        try:
            from PIL import Image
            ims = []
            for f in self.pages:
                im = Image.open(f)
                im.load()
                ims.append(im.convert("RGB"))
            outs = save_pages(ims, p, self.fmt, self.dpi)
        except Exception as e:
            messagebox.showerror("保存失败", str(e), parent=self)
            return

        self.cleanup()
        master = self.master
        self.destroy()
        if len(outs) == 1:
            msg = f"已保存 {len(self.pages)} 页到：\n{outs[0]}"
            target = outs[0]
        else:
            msg = f"已保存 {len(outs)} 个文件到：\n{os.path.dirname(outs[0])}"
            target = os.path.dirname(outs[0])
        if messagebox.askyesno("完成", msg + "\n\n现在打开吗？", parent=master):
            try:
                os.startfile(target)
            except Exception:
                pass

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def on_close(self):
        if self.busy:
            return
        if self.pages and not messagebox.askyesno(
                "放弃", f"还有 {len(self.pages)} 页未保存，确定放弃？", parent=self):
            return
        self.cleanup()
        self.destroy()


# --------------------------------------------------------------------- 界面
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.q = queue.Queue()
        self.busy = False
        self.current = {"xaddr": None, "scanner": None, "model": "", "serial": ""}
        self.caps = {"adf": False, "adf_duplex": False, "feeder_capacity": 0,
                     "adf_dpi": [], "platen_dpi": [], "model": ""}

        self.title(f"{APP_NAME}  v{VERSION}  —  跨网段扫描")
        self.geometry("780x680")
        self.minsize(720, 640)
        apply_icon(self)

        self._build()
        self._restore()
        self.after(120, self._drain)

    # ---------------- 布局
    def _build(self):
        pad = {"padx": 10, "pady": 6}

        # 顶部：连接
        f1 = ttk.LabelFrame(self, text=" 扫描仪连接 ")
        f1.pack(fill="x", **pad)

        row = ttk.Frame(f1)
        row.pack(fill="x", padx=10, pady=8)
        ttk.Label(row, text="IP 地址").pack(side="left")
        self.var_ip = tk.StringVar(value="192.168.1.100")
        self.e_ip = ttk.Entry(row, textvariable=self.var_ip, width=18, font=("Consolas", 11))
        self.e_ip.pack(side="left", padx=(8, 8))
        self.e_ip.bind("<Return>", lambda e: self.do_detect())

        self.btn_detect = ttk.Button(row, text="检测连接", command=self.do_detect)
        self.btn_detect.pack(side="left")
        self.btn_find = ttk.Button(row, text="搜索本网段", command=self.do_search)
        self.btn_find.pack(side="left", padx=6)

        ttk.Label(row, text="最近使用").pack(side="left", padx=(16, 4))
        self.var_hist = tk.StringVar()
        self.cb_hist = ttk.Combobox(row, textvariable=self.var_hist, width=18, state="readonly")
        self.cb_hist.pack(side="left")
        self.cb_hist.bind("<<ComboboxSelected>>", self._pick_hist)

        # 设备信息
        self.lbl_dev = ttk.Label(f1, text="未连接", foreground="#666")
        self.lbl_dev.pack(fill="x", padx=12, pady=(0, 8))

        # 参数
        f2 = ttk.LabelFrame(self, text=" 扫描参数 ")
        f2.pack(fill="x", **pad)
        g = ttk.Frame(f2)
        g.pack(fill="x", padx=10, pady=8)
        for i in range(4):
            g.columnconfigure(i * 2 + 1, weight=1)

        ttk.Label(g, text="分辨率").grid(row=0, column=0, sticky="w")
        self.var_dpi = tk.StringVar(value="300")
        ttk.Combobox(g, textvariable=self.var_dpi, values=DPI_CHOICES, width=8,
                     state="readonly").grid(row=0, column=1, sticky="w", padx=(6, 18))

        ttk.Label(g, text="颜色").grid(row=0, column=2, sticky="w")
        self.var_color = tk.StringVar(value="彩色")
        ttk.Combobox(g, textvariable=self.var_color, values=list(COLOR_MAP), width=8,
                     state="readonly").grid(row=0, column=3, sticky="w", padx=(6, 18))

        ttk.Label(g, text="纸张").grid(row=0, column=4, sticky="w")
        self.var_size = tk.StringVar(value="A4")
        ttk.Combobox(g, textvariable=self.var_size, values=list(SIZE_MAP) + ["自动"],
                     width=8, state="readonly").grid(row=0, column=5, sticky="w", padx=(6, 18))

        ttk.Label(g, text="格式").grid(row=0, column=6, sticky="w")
        self.var_fmt = tk.StringVar(value="PDF")
        ttk.Combobox(g, textvariable=self.var_fmt, values=["PDF", "JPG", "PNG"], width=8,
                     state="readonly").grid(row=0, column=7, sticky="w", padx=(6, 0))

        # 第二行：进纸源 / 横竖版 / 裁剪
        ttk.Label(g, text="进纸源").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.var_src = tk.StringVar(value=SRC_PLATEN)
        self.cb_src = ttk.Combobox(g, textvariable=self.var_src, values=[SRC_PLATEN],
                                   width=8, state="readonly")
        self.cb_src.grid(row=1, column=1, sticky="w", padx=(6, 18), pady=(8, 0))
        self.cb_src.bind("<<ComboboxSelected>>", self._on_src_change)

        ttk.Label(g, text="横竖版").grid(row=1, column=2, sticky="w", pady=(8, 0))
        self.var_rot = tk.StringVar(value="不旋转")
        ttk.Combobox(g, textvariable=self.var_rot, values=list(ROT_CHOICES), width=10,
                     state="readonly").grid(row=1, column=3, sticky="w",
                                            padx=(6, 18), pady=(8, 0))

        self.var_crop = tk.BooleanVar(value=False)
        ttk.Checkbutton(g, text="扫描后裁剪", variable=self.var_crop).grid(
            row=1, column=4, columnspan=2, sticky="w", pady=(8, 0))

        self.lbl_cap = ttk.Label(g, text="", foreground="#888")
        self.lbl_cap.grid(row=1, column=6, columnspan=2, sticky="w", pady=(8, 0))

        # 输出目录
        f3 = ttk.Frame(f2)
        f3.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Label(f3, text="保存到").pack(side="left")
        self.var_dir = tk.StringVar(value=os.path.join(os.path.expanduser("~"), "Pictures"))
        ttk.Entry(f3, textvariable=self.var_dir).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(f3, text="浏览…", command=self._pick_dir).pack(side="left")

        # 动作
        f4 = ttk.Frame(self)
        f4.pack(fill="x", padx=10, pady=(2, 6))
        self.btn_scan = ttk.Button(f4, text="开 始 扫 描", command=self.do_scan)
        self.btn_scan.pack(side="left", ipadx=24, ipady=6)
        self.btn_multi = ttk.Button(f4, text="多页连续扫描", command=self.do_multipage)
        self.btn_multi.pack(side="left", padx=8, ipady=5)
        self.pb = ttk.Progressbar(f4, mode="indeterminate")
        self.pb.pack(side="left", fill="x", expand=True, padx=12)

        # 日志
        f5 = ttk.LabelFrame(self, text=" 运行日志 ")
        f5.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.txt = tk.Text(f5, height=10, wrap="word", font=("Microsoft YaHei UI", 9),
                           bg="#fafafa", relief="flat", state="disabled")
        sb = ttk.Scrollbar(f5, command=self.txt.yview)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)

        self.status = ttk.Label(self, text="就绪", anchor="w", foreground="#555")
        self.status.pack(fill="x", padx=12, pady=(0, 6))

    def _restore(self):
        c = self.cfg
        if c.get("ip"):
            self.var_ip.set(c["ip"])
        for k, v in (("dpi", self.var_dpi), ("color", self.var_color),
                     ("size", self.var_size), ("fmt", self.var_fmt), ("dir", self.var_dir)):
            if c.get(k):
                v.set(c[k])
        if c.get("rot") in ROT_CHOICES:
            self.var_rot.set(c["rot"])
        if c.get("crop"):
            self.var_crop.set(True)
        self._refresh_hist()

    def _persist(self):
        self.cfg.update({
            "ip": self.var_ip.get().strip(), "dpi": self.var_dpi.get(),
            "color": self.var_color.get(), "size": self.var_size.get(),
            "fmt": self.var_fmt.get(), "dir": self.var_dir.get(),
            "rot": self.var_rot.get(), "crop": bool(self.var_crop.get()),
        })
        save_config(self.cfg)

    def _refresh_hist(self):
        hist = self.cfg.get("history", [])
        self.cb_hist["values"] = hist
        if hist and not self.var_hist.get():
            self.var_hist.set(hist[0])

    def _pick_hist(self, _evt=None):
        v = self.var_hist.get()
        if v:
            self.var_ip.set(v.split()[0])

    def _remember(self, ip, model):
        hist = [h for h in self.cfg.get("history", []) if not h.startswith(ip)]
        hist.insert(0, f"{ip}  {model}" if model else ip)
        self.cfg["history"] = hist[:12]
        save_config(self.cfg)
        self._refresh_hist()

    def _pick_dir(self):
        d = filedialog.askdirectory(initialdir=self.var_dir.get() or os.path.expanduser("~"))
        if d:
            self.var_dir.set(d)

    # ---------------- 日志与线程
    def log(self, msg):
        self.q.put(("log", msg))

    def set_status(self, msg):
        self.q.put(("status", msg))

    def _drain(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    self.txt.configure(state="normal")
                    self.txt.insert("end", f"[{datetime.datetime.now():%H:%M:%S}] {val}\n")
                    self.txt.see("end")
                    self.txt.configure(state="disabled")
                elif kind == "status":
                    self.status.configure(text=val)
                elif kind == "device":
                    self.lbl_dev.configure(text=val, foreground="#0a6")
                elif kind == "devfail":
                    self.lbl_dev.configure(text=val, foreground="#b00")
                elif kind == "caps":
                    self._apply_caps(val)
                elif kind == "crop":
                    self._save_with_crop(*val)
                elif kind == "busy":
                    self._set_busy(val)
                elif kind == "refresh_hist":
                    self._refresh_hist()
                elif kind == "done":
                    self._set_busy(False)
                    self.log(f"✔ 完成：{val}")
                    self.set_status("完成")
                    if messagebox.askyesno("扫描完成", f"已保存：\n{val}\n\n现在打开吗？"):
                        try:
                            os.startfile(val)
                        except Exception:
                            pass
                elif kind == "error":
                    self._set_busy(False)
                    self.log(f"✘ {val}")
                    self.set_status("失败")
                    messagebox.showerror("出错了", val)
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _set_busy(self, b):
        self.busy = b
        st = "disabled" if b else "normal"
        self.btn_scan.configure(state=st)
        self.btn_detect.configure(state=st)
        self.btn_find.configure(state=st)
        self.btn_multi.configure(state=st)
        if b:
            self.pb.start(12)
        else:
            self.pb.stop()

    def _host(self):
        h = self.var_ip.get().strip()
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h):
            messagebox.showwarning("IP 格式不对", "请填写完整的 IPv4 地址，例如 192.168.1.100")
            return None
        return h

    # ---------------- 检测
    def do_detect(self):
        if self.busy:
            return
        host = self._host()
        if not host:
            return
        self._set_busy(True)
        self.set_status("检测中…")
        self.log(f"检测 {host} …")

        def work():
            try:
                xaddr = discover(host)
                info = get_scanner(xaddr)
                state, _ = get_state(info["scanner"])
                self.current.update(xaddr=xaddr, scanner=info["scanner"],
                                    model=info["model"], serial=info["serial"])
                self.q.put(("device", f"● {info['model']}   序列号 {info['serial']}   "
                                      f"状态 {state}   {host}"))
                self.q.put(("log", f"扫描服务：{info['scanner']}"))

                # 能力只能从 eSCL 读（WSD 那套在惠普这两代机器上不返回 ScannerCapabilities）
                caps = get_caps(host)
                caps["model"] = caps.get("model") or info["model"]
                self.q.put(("caps", caps))
                if caps["adf"]:
                    paper = get_paper(host)
                    self.q.put(("log", f"检测到进纸器：容量约 {caps['feeder_capacity']} 页，"
                                       f"{'支持双面' if caps['adf_duplex'] else '仅单面'}，"
                                       f"分辨率 {caps['adf_dpi'] or '未知'}，"
                                       f"当前{'有纸' if paper == 'Loaded' else '无纸' if paper == 'Empty' else '纸量未知'}"))
                else:
                    self.q.put(("log", "该设备没有进纸器（只能平板扫描）"))

                self.q.put(("status", "已连接"))
                self._remember(host, info["model"])
                self._persist()
            except Exception as e:
                msg = human_error(e, host)
                self.q.put(("devfail", "● 连接失败：" + msg.split("\n")[0]))
                self.q.put(("error", msg))
            finally:
                self.q.put(("busy", False))

        threading.Thread(target=work, daemon=True).start()

    # ---------------- 进纸源
    def _on_src_change(self, _e=None):
        if self.var_src.get() != SRC_FEEDER:
            return
        if not self.caps.get("adf"):
            messagebox.showwarning(
                "没有进纸器",
                "这台设备没有检测到进纸器，只能用平板扫描。\n\n"
                "（如果确实是带进纸器的机型，先点一下【检测连接】再选。）")
            self.var_src.set(SRC_PLATEN)
            return

        # 惠普这类机型的网络扫描接口（WSD）会忽略 InputSource=Feeder，一律扫平板。
        # 已实测确认：要求 14 英寸高的扫描区（只有进纸器放得下），设备返回约 11.5 英寸，
        # 即按平板的 12 英寸上限钳过了。进纸器在这台机器上只能走打印机面板 + U 盘。
        if not getattr(self, "_feeder_warned", False):
            self._feeder_warned = True
            ok = messagebox.askyesno(
                "进纸器无法通过网络驱动",
                "实测：这台 HP 的网络扫描接口不支持进纸器。\n\n"
                "即使选「进纸器」，设备也会按平板扫描（已用扫描区高度验证过）。\n\n"
                "要用进纸器，只能走打印机面板：\n"
                "  1. 把 U 盘（FAT32）插到打印机前面板的 USB 口\n"
                "  2. 面板选 扫描 → 放好文稿 → 保存到 USB → 选 PDF\n"
                "  3. 扫完把 U 盘插回电脑即可\n\n"
                "点【是】仍按当前设置扫描（结果等同于平板）；\n"
                "点【否】切换回平板。")
            if not ok:
                self.var_src.set(SRC_PLATEN)
                self.log("已切换回平板扫描")
                return
        self.log("注意：这台设备的网络接口不支持进纸器，实际会按平板扫描")

        dpi_ok = self.caps.get("adf_dpi") or []
        if dpi_ok and int(self.var_dpi.get()) not in dpi_ok:
            self.var_dpi.set(str(dpi_ok[-1]))
            self.log(f"进纸器只支持 {'/'.join(map(str, dpi_ok))} dpi，已自动切到 {dpi_ok[-1]}")

    def _apply_caps(self, caps):
        self.caps = caps
        if caps.get("adf"):
            self.cb_src.configure(values=[SRC_PLATEN, SRC_FEEDER])
            self.lbl_cap.configure(
                text=f"进纸器 {caps['feeder_capacity']} 页"
                     f"{' · 双面' if caps['adf_duplex'] else ' · 单面'}",
                foreground="#0a6")
        else:
            self.cb_src.configure(values=[SRC_PLATEN])
            self.var_src.set(SRC_PLATEN)
            self.lbl_cap.configure(text="仅平板", foreground="#888")

    # ---------------- 网段搜索
    def do_search(self):
        if self.busy:
            return
        host = self.var_ip.get().strip()
        m = re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}", host)
        if not m:
            messagebox.showwarning("提示", "请先在 IP 框里填一个本网段的地址，例如 192.168.1.10\n"
                                          "程序会按前三段扫描 1-254。")
            return
        prefix = m.group(1)
        self._set_busy(True)
        self.set_status(f"搜索 {prefix}.1-254 …")
        self.log(f"开始搜索 {prefix}.0/24（约需 10-20 秒）…")

        def probe(i):
            ip = f"{prefix}.{i}"
            try:
                return ip, discover_udp(ip, timeout=1.2)
            except Exception:
                return None

        def work():
            found = []
            try:
                with ThreadPoolExecutor(max_workers=64) as ex:
                    for r in ex.map(probe, range(1, 255)):
                        if r:
                            found.append(r[0])
                            self.q.put(("log", f"  发现设备：{r[0]}"))
                if not found:
                    self.q.put(("log", "本网段未发现扫描设备（可能被防火墙拦了 UDP 3702）"))
                    self.q.put(("status", "未发现设备"))
                else:
                    self.q.put(("log", f"共发现 {len(found)} 台，已填入 IP 框"))
                    self.var_ip.set(found[0])
                    self.cfg["history"] = sorted(set(found + self.cfg.get("history", [])),
                                                 key=lambda x: (x.split()[0] not in found,
                                                                x))[:12]
                    save_config(self.cfg)
                    self.q.put(("refresh_hist", None))
                    self.q.put(("status", f"发现 {len(found)} 台"))
            finally:
                self.q.put(("busy", False))

        threading.Thread(target=work, daemon=True).start()

    # ---------------- 扫描
    def do_scan(self):
        if self.busy:
            return
        host = self._host()
        if not host:
            return
        out_dir = self.var_dir.get()
        if not os.path.isdir(out_dir):
            messagebox.showwarning("目录不存在", "请选择一个存在的保存目录")
            return

        fmt = self.var_fmt.get()
        stamp = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        out_path = os.path.join(out_dir, f"scan-{stamp}.{fmt.lower()}")
        size = self.var_size.get()
        size = None if size == "自动" else size
        dpi = int(self.var_dpi.get())
        source = self.var_src.get()
        rotation = ROT_CHOICES.get(self.var_rot.get(), 0)
        want_crop = bool(self.var_crop.get())

        self._set_busy(True)
        self.set_status("扫描中…")
        self.log(f"开始扫描 {host} → {out_path}"
                 f"（{source} / {dpi}dpi / {self.var_rot.get()}）")

        def prog(m):
            self.q.put(("log", m))
            self.q.put(("status", m))

        def work():
            try:
                im = scan_image(host, dpi, self.var_color.get(), size, prog, source)
                im = apply_rotation(im, rotation)
                if want_crop:
                    tmp = os.path.join(tempfile.gettempdir(),
                                       f"wsdscan_crop_{os.getpid()}.png")
                    im.save(tmp, "PNG")
                    self.q.put(("log", f"图像尺寸 {im.size[0]}×{im.size[1]}，等待框选裁剪…"))
                    self.q.put(("crop", (tmp, out_path, fmt, dpi)))
                    return
                prog("正在保存…")
                if fmt == "PDF":
                    im.save(out_path, "PDF", resolution=float(dpi))
                elif fmt == "JPG":
                    im.save(out_path, "JPEG", quality=92)
                else:
                    im.save(out_path, "PNG")
                self.q.put(("log", f"图像尺寸 {im.size[0]}×{im.size[1]}"))
                self._persist()
                self.q.put(("done", out_path))
            except Exception as e:
                self.q.put(("error", human_error(e, host)))

        threading.Thread(target=work, daemon=True).start()

    def _save_with_crop(self, tmp_path, out_path, fmt, dpi):
        """扫描完成后弹裁剪框，确认后再落盘。"""
        from PIL import Image
        try:
            im = Image.open(tmp_path)
            im.load()
            im = im.convert("RGB")
        except Exception as e:
            self._set_busy(False)
            messagebox.showerror("读取失败", str(e))
            return

        def ok(box, _apply_all, angle=0.0):
            try:
                out = rotate_free(im, angle)      # 先纠偏
                out = crop_rel(out, box)          # 再裁剪
                if fmt == "PDF":
                    out.save(out_path, "PDF", resolution=float(dpi))
                elif fmt == "JPG":
                    out.save(out_path, "JPEG", quality=92)
                else:
                    out.save(out_path, "PNG")
                self.log(f"纠偏 {angle:+.1f}°，裁剪后尺寸 {out.size[0]}×{out.size[1]}")
                self._persist()
                self.q.put(("done", out_path))
            except Exception as e:
                self.q.put(("error", f"保存失败：{e}"))
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        def on_close():
            self._set_busy(False)
            self.set_status("已取消")
            self.log("已取消裁剪，本次扫描未保存")
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        CropDialog(self, im, ok, title="框选要保留的区域", on_cancel=on_close)

    # ---------------- 多页
    def do_multipage(self):
        if self.busy:
            return
        host = self._host()
        if not host:
            return
        out_dir = self.var_dir.get()
        if not os.path.isdir(out_dir):
            messagebox.showwarning("目录不存在", "请选择一个存在的保存目录")
            return
        size = self.var_size.get()
        size = None if size == "自动" else size
        self._persist()
        MultiPageDialog(self, host, int(self.var_dpi.get()), self.var_color.get(),
                        size, self.var_fmt.get(), out_dir,
                        source=self.var_src.get(),
                        rotation=ROT_CHOICES.get(self.var_rot.get(), 0),
                        feeder_max=self.caps.get("feeder_capacity") or 35)
        self.log(f"打开多页扫描窗口（{host} / {self.var_src.get()}）")


if __name__ == "__main__":
    app = App()
    app.mainloop()
