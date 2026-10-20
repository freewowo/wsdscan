<#
  WSD Scan - 打印机连通性与端口体检

  用法: powershell -ExecutionPolicy Bypass -File .\PrinterCheck.ps1 -PrinterIP 192.168.1.100

  作用: 按下标分层缩小范围，判断"扫不到打印机"到底是
        网段不通、端口被 ACL、还是本机 SMB 没开。
#>
[CmdletBinding()]
param(
    [string]$PrinterIP = "192.168.1.100"
)

function Get-Netmask([int]$PrefixLength) {
    $v = [uint32]0
    if ($PrefixLength -gt 0) { $v = ([math]::Pow(2, $PrefixLength) - 1) }
    $v = $v -shl (32 - $PrefixLength)
    $b = [BitConverter]::GetBytes($v)
    [array]::Reverse($b)
    return ($b -join '.')
}

function Test-TcpPort([string]$Ip, [int]$Port, [int]$TimeoutMs = 1500) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $r = $c.BeginConnect($Ip, $Port, $null, $null)
        if ($r.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $c.EndConnect($r)
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $c.Close()
    }
}

Write-Output "========== 1. 本机网卡 =========="
$cfg = Get-NetIPConfiguration
$gw = ($cfg | Where-Object { $_.IPv4DefaultGateway }).IPv4DefaultGateway.NextHop
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | ForEach-Object {
    "网卡     : $($_.InterfaceAlias)"
    "IPv4     : $($_.IPAddress)"
    "掩码     : $(Get-Netmask $_.PrefixLength) (/$($_.PrefixLength))"
}
"网关     : $gw"

Write-Output ""
Write-Output "========== 2. ping 打印机 $PrinterIP =========="
if (Test-Connection -ComputerName $PrinterIP -Count 2 -Quiet) {
    "结果: 通  -> 路由 OK，问题只在扫描发现协议"
} else {
    "结果: 不通 -> 两个网段无路由或被 ACL 拦截，需找网管放行"
}

Write-Output ""
Write-Output "========== 3. 打印机 TCP 端口探测 =========="
$ports = [ordered]@{
    '9100  打印/Raw'       = 9100
    '80    EWS 网页'       = 80
    '443   HTTPS / EWS'    = 443
    '8080  eSCL 备用'      = 8080
    '631   IPP'            = 631
}
foreach ($k in $ports.Keys) {
    if (Test-TcpPort $PrinterIP $ports[$k]) {
        "  [开放] $k"
    } else {
        "  [关闭] $k"
    }
}

Write-Output ""
Write-Output "========== 4. 反向: 打印机 -> 本机 SMB(445) =========="
$smb = Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue
if ($smb) {
    "本机 445 正在监听。配 SMB 扫描到本机时，需网管放行 打印机->电脑 的 TCP 445（最常被漏放的方向）"
} else {
    "本机 445 未监听，需在网络适配器里启用 SMB 直通 / 文件和打印机共享"
}

Write-Output ""
Write-Output "========== 5. WSD 通道（TCP 3911）=========="
if (Test-TcpPort $PrinterIP 3911) {
    "结果: 开放 -> 可以用 WSD Scan 直连，填这个 IP 即可"
} else {
    "结果: 关闭 -> 设备没起 WSD 扫描服务；确认型号支持，或重新插电/重启打印机"
}
Write-Output ""
