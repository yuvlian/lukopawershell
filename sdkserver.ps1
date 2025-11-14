using namespace System.Collections.Generic
using namespace System.Text
using namespace System.Net

class ProtoWriter {
    [List[byte]] $Buffer
    [HashSet[Int32]] $UsedFields

    ProtoWriter() {
        $this.Buffer = [List[byte]]::new()
        $this.UsedFields = [HashSet[Int32]]::new()
    }

    hidden [void] AddByte([byte] $b) {
        $this.Buffer.Add($b)
    }

    hidden [void] AddBytes([byte[]] $bytes) {
        foreach ($b in $bytes) {
            $this.Buffer.Add($b)
        }
    }

    hidden [void] WriteVarint([UInt64] $value) {
        while ($value -gt 0x7F) {
            $this.AddByte([byte](0x80 -bor ($value -band 0x7F)))
            $value = $value -shr 7
        }
        $this.AddByte([byte]$value)
    }

    hidden [void] CheckField([Int32] $fieldNumber, [Int32] $wireType, [bool] $allowRepeated) {
        if (-not $allowRepeated -and $this.UsedFields.Contains($fieldNumber)) {
            throw "$fieldNumber already written && !repeated"
        }
        $this.UsedFields.Add($fieldNumber) | Out-Null
        $tag = ($fieldNumber -shl 3) -bor $wireType
        $this.WriteVarint([UInt64]$tag)
    }

    [void] WriteUInt32([Int32] $fieldNumber, [UInt32] $value, [bool] $repeated) {
        $this.CheckField($fieldNumber, 0, $repeated)
        $this.WriteVarint([UInt64]$value)
    }

    [void] WriteBool([Int32] $fieldNumber, [bool] $value, [bool] $repeated) {
        $this.CheckField($fieldNumber, 0, $repeated)
        $this.WriteVarint($(if ($value) { 1 } else { 0 }))
    }

    [void] WriteString([Int32] $fieldNumber, [string] $value, [bool] $repeated) {
        $this.CheckField($fieldNumber, 2, $repeated)
        $bytes = [Encoding]::UTF8.GetBytes($value)
        $this.WriteVarint([UInt64]$bytes.Length)
        $this.AddBytes($bytes)
    }

    [void] WriteMessage([Int32] $fieldNumber, [byte[]] $msgBytes, [bool] $repeated) {
        $this.CheckField($fieldNumber, 2, $repeated)
        $this.WriteVarint([UInt64]$msgBytes.Length)
        $this.AddBytes($msgBytes)
    }

    [byte[]] GetBytes() {
        return $this.Buffer.ToArray()
    }
}

class RegionInfo {
    static [int] $FIELD_name = 1
    static [int] $FIELD_title = 2
    static [int] $FIELD_dispatch_url = 3
    static [int] $FIELD_env_type = 4
    static [int] $FIELD_display_name = 5
    static [int] $FIELD_msg = 6

    [string] $name
    [string] $title
    [string] $dispatch_url
    [string] $env_type
    [string] $display_name
    [string] $msg

    RegionInfo() { }

    [byte[]] Encode() {
        $w = [ProtoWriter]::new()

        if ($this.name) { $w.WriteString([RegionInfo]::FIELD_name, $this.name, $false) }
        if ($this.title) { $w.WriteString([RegionInfo]::FIELD_title, $this.title, $false) }
        if ($this.dispatch_url) { $w.WriteString([RegionInfo]::FIELD_dispatch_url, $this.dispatch_url, $false) }
        if ($this.env_type) { $w.WriteString([RegionInfo]::FIELD_env_type, $this.env_type, $false) }
        if ($this.display_name) { $w.WriteString([RegionInfo]::FIELD_display_name, $this.display_name, $false) }
        if ($this.msg) { $w.WriteString([RegionInfo]::FIELD_msg, $this.msg, $false) }

        return $w.GetBytes()
    }
}


class Dispatch {
    static [int] $FIELD_retcode = 1
    static [int] $FIELD_msg = 2
    static [int] $FIELD_top_server_region = 3
    static [int] $FIELD_region_list = 4
    static [int] $FIELD_stop_desc = 5

    [UInt32] $retcode
    [string] $msg
    [string] $top_sever_region_name
    [List[RegionInfo]] $region_list
    [string] $stop_desc

    Dispatch() { }

    [byte[]] Encode() {
        $w = [ProtoWriter]::new()

        if ($this.retcode -gt 0) { $w.WriteUInt32([Dispatch]::FIELD_retcode, $this.retcode, $false) }
        if ($this.msg) { $w.WriteString([Dispatch]::FIELD_msg, $this.msg, $false) }
        if ($this.top_sever_region_name) { 
            $w.WriteString([Dispatch]::FIELD_top_server_region, $this.top_sever_region_name, $false) 
        }
        if ($this.region_list) {
            foreach ($region in $this.region_list) {
                $bytes = $region.Encode()
                $w.WriteMessage([Dispatch]::FIELD_region_list, $bytes, $true)
            }
        }
        if ($this.stop_desc) { $w.WriteString([Dispatch]::FIELD_stop_desc, $this.stop_desc, $false) }

        return $w.GetBytes()
    }
}

class GateServer {
    static [int] $FIELD_region_name = 5
    static [int] $FIELD_ip = 6
    static [int] $FIELD_unk1 = 8
    static [int] $FIELD_lua_url = 9
    static [int] $FIELD_ex_resource_url = 10
    static [int] $FIELD_unk2 = 11
    static [int] $FIELD_asset_bundle_url = 12
    static [int] $FIELD_port = 13
    static [int] $FIELD_unk3 = 164
    static [int] $FIELD_unk4 = 298
    static [int] $FIELD_unk5 = 644
    static [int] $FIELD_unk6 = 783
    static [int] $FIELD_client_secret_key = 936
    static [int] $FIELD_msg = 988
    static [int] $FIELD_unk7 = 1000
    static [int] $FIELD_unk8 = 1141
    static [int] $FIELD_asset_bundle_url_android = 1421
    static [int] $FIELD_unk9 = 1750
    static [int] $FIELD_ifix_url = 1813
    static [int] $FIELD_unk10 = 1983
    static [int] $FIELD_ifix_version = 652
    static [int] $FIELD_mdk_res_version = 1150
    static [int] $FIELD_use_tcp = 1759

    [string] $region_name
    [string] $ip
    [bool]   $unk1
    [string] $lua_url
    [string] $ex_resource_url
    [bool]   $unk2
    [string] $asset_bundle_url
    [UInt32] $port
    [bool]   $unk3
    [bool]   $unk4
    [bool]   $unk5
    [bool]   $unk6
    [string] $client_secret_key
    [string] $msg
    [bool]   $unk7
    [bool]   $unk8
    [string] $asset_bundle_url_android
    [bool]   $unk9
    [string] $ifix_url
    [bool]   $unk10
    [string] $ifix_version
    [string] $mdk_res_version
    [bool]   $use_tcp

    GateServer() { }

    [byte[]] Encode() {
        $w = [ProtoWriter]::new()

        if ($this.region_name) { $w.WriteString([GateServer]::FIELD_region_name, $this.region_name, $false) }
        if ($this.ip) { $w.WriteString([GateServer]::FIELD_ip, $this.ip, $false) }
        if ($this.unk1) { $w.WriteBool([GateServer]::FIELD_unk1, $this.unk1, $false) }
        if ($this.lua_url) { $w.WriteString([GateServer]::FIELD_lua_url, $this.lua_url, $false) }
        if ($this.ex_resource_url) { $w.WriteString([GateServer]::FIELD_ex_resource_url, $this.ex_resource_url, $false) }
        if ($this.unk2) { $w.WriteBool([GateServer]::FIELD_unk2, $this.unk2, $false) }
        if ($this.asset_bundle_url) { $w.WriteString([GateServer]::FIELD_asset_bundle_url, $this.asset_bundle_url, $false) }
        if ($this.port -gt 0) { $w.WriteUInt32([GateServer]::FIELD_port, $this.port, $false) }
        if ($this.unk3) { $w.WriteBool([GateServer]::FIELD_unk3, $this.unk3, $false) }
        if ($this.unk4) { $w.WriteBool([GateServer]::FIELD_unk4, $this.unk4, $false) }
        if ($this.unk5) { $w.WriteBool([GateServer]::FIELD_unk5, $this.unk5, $false) }
        if ($this.unk6) { $w.WriteBool([GateServer]::FIELD_unk6, $this.unk6, $false) }
        if ($this.client_secret_key) { $w.WriteString([GateServer]::FIELD_client_secret_key, $this.client_secret_key, $false) }
        if ($this.msg) { $w.WriteString([GateServer]::FIELD_msg, $this.msg, $false) }
        if ($this.unk7) { $w.WriteBool([GateServer]::FIELD_unk7, $this.unk7, $false) }
        if ($this.unk8) { $w.WriteBool([GateServer]::FIELD_unk8, $this.unk8, $false) }
        if ($this.asset_bundle_url_android) { $w.WriteString([GateServer]::FIELD_asset_bundle_url_android, $this.asset_bundle_url_android, $false) }
        if ($this.unk9) { $w.WriteBool([GateServer]::FIELD_unk9, $this.unk9, $false) }
        if ($this.ifix_url) { $w.WriteString([GateServer]::FIELD_ifix_url, $this.ifix_url, $false) }
        if ($this.unk10) { $w.WriteBool([GateServer]::FIELD_unk10, $this.unk10, $false) }
        if ($this.ifix_version) { $w.WriteString([GateServer]::FIELD_ifix_version, $this.ifix_version, $false) }
        if ($this.mdk_res_version) { $w.WriteString([GateServer]::FIELD_mdk_res_version, $this.mdk_res_version, $false) }
        if ($this.use_tcp) { $w.WriteBool([GateServer]::FIELD_use_tcp, $this.use_tcp, $false) }

        return $w.GetBytes()
    }
}

function Write-HttpResponse {
    param(
        [HttpListenerResponse] $Response,
        [string] $Body,
        [UInt16] $StatusCode
    )
    $bytes = [Encoding]::UTF8.GetBytes($Body)
    $Response.StatusCode = $StatusCode
    $Response.ContentLength64 = $bytes.Length
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Response.OutputStream.Close()
}

function HandleRiskyCheck {
    return @'
{
    "data": {},
    "message": "OK",
    "retcode": 0
}
'@
}

function HandleShieldThings {
    return @'
{
    "data": {
        "account": {
            "area_code": "**",
            "country": "ID",
            "email": "yuvlian@naver.com",
            "is_email_verify": "1",
            "token": "x",
            "uid": "1"
        },
        "device_grant_required": false,
        "reactivate_required": false,
        "realperson_required": false,
        "safe_mobile_required": false
    },
    "message": "OK",
    "retcode": 0
}
'@
}

function HandleTokenLogin {
    return @'
{
    "data": {
        "account_type": 1,
        "combo_id": "1",
        "combo_token": "x",
        "data": "{\"guest\":false}",
        "heartbeat": false,
        "open_id": "1"
    },
    "message": "OK",
    "retcode": 0
}
'@
}

function HandlePasswordLogin {
    return @'
{
    "data": {
        "bind_email_action_ticket": "",
        "ext_user_info": {
            "birth": "0",
            "guardian_email": ""
        },
        "reactivate_action_token": "",
        "token": {
            "token_type": 1,
            "token": "x"
        },
        "user_info": {
            "account_name": "yulian",
            "aid": "1",
            "area_code": "**",
            "token": "x",
            "email": "yuvlian@naver.com",
            "is_email_verify": "1",
            "country": "ID"
        }
    },
    "message": "OK",
    "retcode": 0
}
'@
}

function HandleQueryDispatch {
    $ri = [RegionInfo]::new()
    $ri.name = "shell"
    $ri.display_name = "shell"
    $ri.title = "shell"
    $ri.env_type = "2"
    $ri.msg = "OK"
    $ri.dispatch_url = "http://127.0.0.1:21000/query_gateway"

    $dp = [Dispatch]::new()
    $dp.retcode = 0
    $dp.msg = "OK"
    $dp.top_sever_region_name = "shell"
    $dp.region_list = [List[RegionInfo]]::new()
    $dp.region_list.Add($ri)

    $buf = $dp.Encode()
    return [Convert]::ToBase64String($buf)
}

function HandleQueryGateway {
    $gs = [GateServer]::new()

    $gs.ip = "127.0.0.1"
    $gs.unk1 = $true
    $gs.lua_url = ""
    $gs.ex_resource_url = ""
    $gs.unk2 = $true
    $gs.asset_bundle_url = ""
    $gs.port = 23301
    $gs.unk3 = $true
    $gs.unk4 = $true
    $gs.unk5 = $true
    $gs.unk6 = $true
    $gs.unk7 = $true
    $gs.unk8 = $true
    $gs.unk9 = $true
    $gs.ifix_url = ""
    $gs.unk10 = $true
    $gs.ifix_version = "0"
    $gs.mdk_res_version = ""
    $gs.use_tcp = $true

    $buf = $gs.Encode()
    return [Convert]::ToBase64String($buf)
}

$sdkserver = [HttpListener]::new()
$sdkserver.Prefixes.Add("http://localhost:21000/")

try {
    $sdkserver.Start()
    Write-Host "sdkserver @ http://localhost:21000/"
}
catch {
    Write-Error "failed to start sdkserver: $($_.Exception.Message)"
    exit
}

while ($sdkserver.IsListening) {
    try {
        $ctx = $sdkserver.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response

        $route = $req.Url.AbsolutePath
        Write-Host "route hit: $route"

        switch ($route) {
            "/query_dispatch" {
                Write-HttpResponse -Response $res -Body (HandleQueryDispatch) -StatusCode 200
                break
            }
            "/query_gateway" {
                Write-HttpResponse -Response $res -Body (HandleQueryGateway) -StatusCode 200
                break
            }
            "/account/risky/api/check" {
                Write-HttpResponse -Response $res -Body (HandleRiskyCheck) -StatusCode 200
                break
            }
            "/hkrpg_global/combo/granter/login/v2/login" {
                Write-HttpResponse -Response $res -Body (HandleTokenLogin) -StatusCode 200
                break
            }
            "/hkrpg_global/account/ma-passport/api/appLoginByPassword" {
                Write-HttpResponse -Response $res -Body (HandlePasswordLogin) -StatusCode 200
                break
            }
            "/hkrpg_global/mdk/shield/api/login" {
                Write-HttpResponse -Response $res -Body (HandleShieldThings) -StatusCode 200
                break
            }
            "/hkrpg_global/mdk/shield/api/verify" {
                Write-HttpResponse -Response $res -Body (HandleShieldThings) -StatusCode 200
                break
            }
            default {
                Write-HttpResponse -Response $res -Body "not found" -StatusCode 404
            }
        }
    }
    catch [System.ObjectDisposedException] {
        break
    }
    catch {
        Write-Host "sdkserver error: $($_.Exception.Message)"
    }
}

$sdkserver.Close()
Write-Host "sdkserver closed."
