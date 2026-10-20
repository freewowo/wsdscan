#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wsdscan.py —— 跨网段网络扫描工具（WS-Scan / WSD）

用途：直接指定打印机 IP 扫描，不依赖 mDNS / 广播发现，因此可以跨网段使用。

原理：
  1. 向目标 IP 的 3702 端口发定向 WS-Discovery Probe（单播，不经组播，故可跨网段）
  2. 从回包拿到设备 WSD 端点，再 WS-Transfer Get 读出扫描服务地址
  3. CreateScanJob 建任务 -> RetrieveImage 取图（MTOM）
  4. 本地用 Pillow 把 BMP 转成 PDF / JPG / PNG

用法示例：
  python wsdscan.py --host 192.168.1.100
  python wsdscan.py --host 192.168.1.100 --dpi 600 --mode color --format jpg
  python wsdscan.py --host 192.168.1.100 --info
"""

import argparse
import base64
import datetime
import email
import os
import re
import socket
import sys
import urllib.error
import urllib.request
import uuid

DISCOVERY_PORT = 3702
WS_SCAN_NS = "http://schemas.microsoft.com/windows/2006/08/wdp/scan"
ACT = WS_SCAN_NS + "/"


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- 1. 定向发现
def discover(host, timeout=4.0):
    """向 host:3702 单播 WS-Discovery Probe，返回 (uuid, xaddr)。"""
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
    except socket.timeout:
        raise RuntimeError(
            f"{host}:{DISCOVERY_PORT} 无响应。\n"
            f"  可能原因：打印机没开机 / IP 不对 / 防火墙拦了 UDP 3702。"
        )
    finally:
        s.close()

    txt = raw.decode("utf-8", "replace")
    if "wscn:ScanDeviceType" not in txt and "ScanDeviceType" not in txt:
        log("  ! 该设备未声明扫描能力（不是扫描设备）")
    m = re.search(r"<[^>]*XAddrs[^>]*>([^<]+)<", txt)
    if not m:
        raise RuntimeError("回包里没有 XAddrs，设备可能未启用 Web 服务")
    xaddr = m.group(1).split()[0]
    u = re.search(r"urn:uuid:([0-9a-fA-F\-]{36})", txt)
    return (u.group(1) if u else None), xaddr


# ------------------------------------------------------- 2. WSD 元数据 / 服务
def soap_post(url, action, body, ns_extra="", timeout=60):
    ns = ('xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
          'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
          'xmlns:wscn="' + WS_SCAN_NS + '" ' + ns_extra)
    env = (f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope {ns}>'
           f'<soap:Header><wsa:To>{url}</wsa:To><wsa:Action>{action}</wsa:Action>'
           f'<wsa:MessageID>urn:uuid:{uuid.uuid4()}</wsa:MessageID>'
           '<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>'
           f'</soap:Header><soap:Body>{body}</soap:Body></soap:Envelope>').encode("utf-8")
    req = urllib.request.Request(url, data=env, method="POST")
    req.add_header("Content-Type", "application/soap+xml; charset=utf-8")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.headers.get("Content-Type", ""), r.read()


def find_scanner_url(xaddr):
    """WS-Transfer Get 取设备元数据，找出扫描服务地址。"""
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
    with urllib.request.urlopen(req, timeout=20) as r:
        txt = r.read().decode("utf-8", "replace")

    model = re.search(r"<wdp:ModelName>([^<]+)<", txt)
    serial = re.search(r"<wdp:SerialNumber>([^<]+)<", txt)
    name = re.search(r"<wdp:FriendlyName>([^<]+)<", txt)
    info = {
        "model": model.group(1) if model else "?",
        "serial": serial.group(1) if serial else "?",
        "name": name.group(1) if name else "?",
    }

    # 找出 ScannerServiceType 对应的 EndpointReference Address
    for blk in re.findall(r"<wdp:Hosted>(.*?)</wdp:Hosted>", txt, re.S):
        if "ScannerServiceType" in blk:
            a = re.search(r"<wsa:Address>([^<]+)<", blk)
            if a:
                info["scanner"] = a.group(1)
                return info
    raise RuntimeError("设备元数据里找不到扫描服务（可能禁用了 WSD 扫描）")


def get_default_ticket(scanner_url):
    body = ("<wscn:GetScannerElementsRequest><wscn:RequestedElements>"
            "<wscn:Name>wscn:DefaultScanTicket</wscn:Name>"
            "</wscn:RequestedElements></wscn:GetScannerElementsRequest>")
    _, d = soap_post(scanner_url, ACT + "GetScannerElements", body)
    txt = d.decode("utf-8", "replace")
    m = re.search(r"<wscn:DefaultScanTicket>(.*?)</wscn:DefaultScanTicket>", txt, re.S)
    if not m:
        raise RuntimeError("读不到默认扫描参数")
    return m.group(1)


# ------------------------------------------------------------- 3. 扫描主流程
COLOR_MAP = {"color": "RGB24", "gray": "Grayscale8", "bw": "BlackAndWhite1"}


def create_job(scanner_url, ticket, dpi, color, size):
    t = ticket
    t = re.sub(r"<wscn:Format>[^<]*</wscn:Format>", "<wscn:Format>dib</wscn:Format>", t)
    t = re.sub(r"<wscn:ColorProcessing>[^<]*</wscn:ColorProcessing>",
               f"<wscn:ColorProcessing>{COLOR_MAP[color]}</wscn:ColorProcessing>", t)
    t = re.sub(r"<wscn:Resolution>\s*<wscn:Width>\d+</wscn:Width>\s*<wscn:Height>\d+</wscn:Height>\s*</wscn:Resolution>",
               f"<wscn:Resolution><wscn:Width>{dpi}</wscn:Width><wscn:Height>{dpi}</wscn:Height></wscn:Resolution>", t)

    if size:
        w, h = {"a4": (8270, 11690), "letter": (8500, 11000)}[size]
        t = re.sub(r"<wscn:InputMediaSize>\s*<wscn:Width>\d+</wscn:Width>\s*<wscn:Height>\d+</wscn:Height>\s*</wscn:InputMediaSize>",
                   f"<wscn:InputMediaSize><wscn:Width>{w}</wscn:Width><wscn:Height>{h}</wscn:Height></wscn:InputMediaSize>", t)
        t = re.sub(r"<wscn:ScanRegionWidth>\d+</wscn:ScanRegionWidth>",
                   f"<wscn:ScanRegionWidth>{w}</wscn:ScanRegionWidth>", t)
        t = re.sub(r"<wscn:ScanRegionHeight>\d+</wscn:ScanRegionHeight>",
                   f"<wscn:ScanRegionHeight>{h}</wscn:ScanRegionHeight>", t)

    body = ("<wscn:CreateScanJobRequest><wscn:ScanTicket>" + t +
            "</wscn:ScanTicket><wscn:DestinationToken>ScanDestination</wscn:DestinationToken>"
            "</wscn:CreateScanJobRequest>")
    try:
        _, d = soap_post(scanner_url, ACT + "CreateScanJob", body, timeout=120)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        sub = re.search(r"<SOAP-ENV:Value>(wscn:[^<]+)</SOAP-ENV:Value>", raw)
        raise RuntimeError(f"创建扫描任务失败：{sub.group(1) if sub else raw[:300]}")
    txt = d.decode("utf-8", "replace")
    jid = re.search(r"<wscn:JobId>(\d+)</wscn:JobId>", txt)
    tok = re.search(r"<wscn:JobToken>([^<]+)</wscn:JobToken>", txt)
    if not jid or not tok:
        raise RuntimeError("创建扫描任务失败，未返回 JobId")
    return jid.group(1), tok.group(1)


def retrieve_image(scanner_url, jid, token):
    body = (f"<wscn:RetrieveImageRequest><wscn:JobId>{jid}</wscn:JobId>"
            f"<wscn:JobToken>{token}</wscn:JobToken>"
            "<wscn:DocumentDescription><wscn:DocumentName>Scan</wscn:DocumentName>"
            "</wscn:DocumentDescription></wscn:RetrieveImageRequest>")
    ct, data = soap_post(scanner_url, ACT + "RetrieveImage", body, timeout=300)

    if ct.startswith("multipart"):
        msg = email.message_from_bytes(b"Content-Type: " + ct.encode() + b"\r\n\r\n" + data)
        for part in msg.walk():
            if (part.get("Content-Type", "")).startswith("image"):
                return part.get_payload(decode=True)
        raise RuntimeError("MTOM 响应里没找到图像数据")

    m = re.search(rb"<wscn:ScanData>([A-Za-z0-9+/=\s]+)</wscn:ScanData>", data)
    if m:
        return base64.b64decode(re.sub(rb"\s", b"", m.group(1)))
    raise RuntimeError("响应里没找到图像数据")


# ------------------------------------------------------------------ 4. 保存
def save_image(raw, out_path, fmt):
    try:
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(raw))
        if fmt == "pdf":
            im.convert("RGB").save(out_path, "PDF", resolution=300.0)
        elif fmt == "jpg":
            im.convert("RGB").save(out_path, "JPEG", quality=90)
        else:
            im.save(out_path, "PNG")
        return im.size
    except ImportError:
        fallback = os.path.splitext(out_path)[0] + ".bmp"
        with open(fallback, "wb") as f:
            f.write(raw)
        log(f"  ! 未安装 Pillow，已存为原始 BMP：{fallback}")
        log("    安装后可转 PDF/JPG：pip install pillow")
        return None


def main():
    ap = argparse.ArgumentParser(description="跨网段网络扫描（WS-Scan）")
    ap.add_argument("--host", required=True, help="打印机 IP，例如 192.168.1.100")
    ap.add_argument("--dpi", type=int, default=300, help="分辨率，默认 300")
    ap.add_argument("--mode", default="color", choices=list(COLOR_MAP), help="color / gray / bw")
    ap.add_argument("--size", default=None, choices=["a4", "letter"], help="纸张，默认用打印机默认值")
    ap.add_argument("--format", default="pdf", choices=["pdf", "jpg", "png"], help="输出格式，默认 pdf")
    ap.add_argument("--out", default=None, help="输出文件路径")
    ap.add_argument("--info", action="store_true", help="只显示设备信息，不扫描")
    args = ap.parse_args()

    log(f"[1/4] 定向发现 {args.host} ...")
    dev_uuid, xaddr = discover(args.host)
    log(f"      端点：{xaddr}")

    log("[2/4] 读取设备信息 ...")
    info = find_scanner_url(xaddr)
    log(f"      型号：{info['model']}    序列号：{info['serial']}")
    log(f"      扫描服务：{info['scanner']}")

    if args.info:
        ticket = get_default_ticket(info["scanner"])
        log("      默认参数（节选）：")
        for tag in ("Format", "InputSource", "ColorProcessing", "Width", "Height"):
            vals = re.findall(rf"<wscn:{tag}>([^<]*)</wscn:{tag}>", ticket)
            if vals:
                log(f"        {tag}: {', '.join(sorted(set(vals))[:6])}")
        return 0

    ticket = get_default_ticket(info["scanner"])

    log(f"[3/4] 创建扫描任务（{args.dpi}dpi / {args.mode}）... 请稍候，扫描仪会开始工作")
    jid, token = create_job(info["scanner"], ticket, args.dpi, args.mode, args.size)

    log(f"[4/4] 取回图像（JobId={jid}）...")
    raw = retrieve_image(info["scanner"], jid, token)
    log(f"      收到 {len(raw)/1024/1024:.1f} MB 原始数据")

    if not args.out:
        stamp = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        base = os.path.join(os.path.expanduser("~"), "Pictures")
        os.makedirs(base, exist_ok=True)
        args.out = os.path.join(base, f"scan-{stamp}.{args.format}")

    size = save_image(raw, args.out, args.format)
    if size:
        log(f"完成：{args.out}   尺寸 {size[0]}x{size[1]}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        log(f"\n[失败] {e}")
        sys.exit(1)
