using namespace System.Collections.Generic
using namespace System.Text
using namespace System.Net
using namespace System.Net.Sockets
using namespace System.IO
using namespace System

function Read-Full {
    param([Stream]$stream, [byte[]]$buffer, [int]$count)

    $offset = 0
    while ($offset -lt $count) {
        $r = $stream.Read($buffer, $offset, $count - $offset)
        if ($r -le 0) { throw "connection closed" }
        $offset += $r
    }
}

function read_u16_be([byte[]]$b) {
    return ([uint16]$b[0] -shl 8) -bor $b[1]
}

function read_u32_be([byte[]]$b) {
    return ([uint32]$b[0] -shl 24) -bor
           ([uint32]$b[1] -shl 16) -bor
           ([uint32]$b[2] -shl 8) -bor
           $b[3]
}

function write_u16_be([uint16]$v) {
    return [byte[]]@(
        ($v -shr 8) -band 0xFF
        $v -band 0xFF
    )
}

function write_u32_be([uint32]$v) {
    return [byte[]]@(
        ($v -shr 24) -band 0xFF
        ($v -shr 16) -band 0xFF
        ($v -shr 8) -band 0xFF
        $v -band 0xFF
    )
}

class Packet {
    [uint16] $cmd
    [byte[]] $head
    [byte[]] $body

    hidden static [byte[]] $head_magic = [byte[]](0x9D, 0x74, 0xC7, 0x14)
    hidden static [byte[]] $tail_magic = [byte[]](0xD7, 0xA1, 0x52, 0xC8)

    Packet([uint16]$cmd, [byte[]]$head, [byte[]]$body) {
        $this.cmd = $cmd
        $this.head = $head
        $this.body = $body
    }

    static [Packet] read_packet([Stream]$stream) {
        $header = New-Object byte[] 12
        Read-Full $stream $header 12

        for ($i = 0; $i -lt 4; $i++) {
            if ($header[$i] -ne [Packet]::head_magic[$i]) {
                throw "invalid head magic"
            }
        }

        $ccmd      = read_u16_be $header[4..5]
        $head_len = read_u16_be $header[6..7]
        $body_len = read_u32_be $header[8..11]

        $hhead = New-Object byte[] $head_len
        if ($head_len -gt 0) {
            Read-Full $stream $hhead $head_len
        }

        $bbody = New-Object byte[] $body_len
        if ($body_len -gt 0) {
            Read-Full $stream $bbody $body_len
        }

        $tail = New-Object byte[] 4
        Read-Full $stream $tail 4

        for ($i = 0; $i -lt 4; $i++) {
            if ($tail[$i] -ne [Packet]::tail_magic[$i]) {
                throw "invalid tail magic"
            }
        }

        return [Packet]::new($ccmd, $hhead, $bbody)
    }

    [byte[]] encode() {
        $head_len = [uint16]$this.head.Length
        $body_len = [uint32]$this.body.Length

        $total = 4 + 2 + 2 + 4 + $head_len + $body_len + 4
        $packet = New-Object byte[] $total
        $offset = 0

        [Array]::Copy([Packet]::head_magic, 0, $packet, $offset, 4)
        $offset += 4

        $cmd_be = write_u16_be $this.cmd
        [Array]::Copy($cmd_be, 0, $packet, $offset, 2)
        $offset += 2

        $hl_be = write_u16_be $head_len
        [Array]::Copy($hl_be, 0, $packet, $offset, 2)
        $offset += 2

        $bl_be = write_u32_be $body_len
        [Array]::Copy($bl_be, 0, $packet, $offset, 4)
        $offset += 4

        if ($head_len -gt 0) {
            [Array]::Copy($this.head, 0, $packet, $offset, $head_len)
            $offset += $head_len
        }

        if ($body_len -gt 0) {
            [Array]::Copy($this.body, 0, $packet, $offset, $body_len)
            $offset += $body_len
        }

        [Array]::Copy([Packet]::tail_magic, 0, $packet, $offset, 4)

        return $packet
    }
}

$FieldNums = [Dictionary[string, int32]]::new()

$FieldNumsPath = "fieldnums.txt"
if (-not (Test-Path $FieldNumsPath)) {
    Write-Error "File not found: $FieldNumsPath"
    return
}
foreach ($line in Get-Content $FieldNumsPath) {
    $line = $line.Trim()
    if ($line -eq "" -or $line.StartsWith("#") -or $line.StartsWith("//")) {
        continue
    }
    $parts = $line -split "="
    if ($parts.Count -ne 2) {
        continue
    }
    $key = $parts[0].Trim()
    $value = [int32]($parts[1].Trim())
    $FieldNums[$key] = $value
}

function Get-FieldNum {
    param([string] $Key)

    if (-not $FieldNums.ContainsKey($Key)) {
        throw "$Key not found in fieldnums"
    }

    return $FieldNums[$Key]
}

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

$DummyMap = [Dictionary[int32, int32]]::new()
$DummyMap[ (Get-FieldNum "CmdId.GetLevelRewardTakenListCsReq") ] = (Get-FieldNum "CmdId.GetLevelRewardTakenListScRsp")
$DummyMap[ (Get-FieldNum "CmdId.QueryProductInfoCsReq") ] = (Get-FieldNum "CmdId.QueryProductInfoScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetQuestDataCsReq") ] = (Get-FieldNum "CmdId.GetQuestDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetQuestRecordCsReq") ] = (Get-FieldNum "CmdId.GetQuestRecordScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetCurAssistCsReq") ] = (Get-FieldNum "CmdId.GetCurAssistScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetDailyActiveInfoCsReq") ] = (Get-FieldNum "CmdId.GetDailyActiveInfoScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetFightActivityDataCsReq") ] = (Get-FieldNum "CmdId.GetFightActivityDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetShareDataCsReq") ] = (Get-FieldNum "CmdId.GetShareDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetTreasureDungeonActivityDataCsReq") ] = (Get-FieldNum "CmdId.GetTreasureDungeonActivityDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetPlayerBoardDataCsReq") ] = (Get-FieldNum "CmdId.GetPlayerBoardDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetActivityScheduleConfigCsReq") ] = (Get-FieldNum "CmdId.GetActivityScheduleConfigScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetMissionDataCsReq") ] = (Get-FieldNum "CmdId.GetMissionDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetChallengeCsReq") ] = (Get-FieldNum "CmdId.GetChallengeScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetCurChallengeCsReq") ] = (Get-FieldNum "CmdId.GetCurChallengeScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetExpeditionDataCsReq") ] = (Get-FieldNum "CmdId.GetExpeditionDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetJukeboxDataCsReq") ] = (Get-FieldNum "CmdId.GetJukeboxDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.SyncClientResVersionCsReq") ] = (Get-FieldNum "CmdId.SyncClientResVersionScRsp")
$DummyMap[ (Get-FieldNum "CmdId.DailyFirstMeetPamCsReq") ] = (Get-FieldNum "CmdId.DailyFirstMeetPamScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetLoginActivityCsReq") ] = (Get-FieldNum "CmdId.GetLoginActivityScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetRaidInfoCsReq") ] = (Get-FieldNum "CmdId.GetRaidInfoScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetTrialActivityDataCsReq") ] = (Get-FieldNum "CmdId.GetTrialActivityDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetNpcStatusCsReq") ] = (Get-FieldNum "CmdId.GetNpcStatusScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetSecretKeyInfoCsReq") ] = (Get-FieldNum "CmdId.GetSecretKeyInfoScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetVideoVersionKeyCsReq") ] = (Get-FieldNum "CmdId.GetVideoVersionKeyScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetCurBattleInfoCsReq") ] = (Get-FieldNum "CmdId.GetCurBattleInfoScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetPhoneDataCsReq") ] = (Get-FieldNum "CmdId.GetPhoneDataScRsp")
$DummyMap[ (Get-FieldNum "CmdId.InteractPropCsReq") ] = (Get-FieldNum "CmdId.InteractPropScRsp")
$DummyMap[ (Get-FieldNum "CmdId.FinishTalkMissionCsReq") ] = (Get-FieldNum "CmdId.FinishTalkMissionScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetRechargeGiftInfoCsReq") ] = (Get-FieldNum "CmdId.GetRechargeGiftInfoScRsp")
$DummyMap[ (Get-FieldNum "CmdId.GetBagCsReq") ] = (Get-FieldNum "CmdId.GetBagScRsp")
$DummyMap[ (Get-FieldNum "CmdId.PlayerLoginFinishCsReq") ] = (Get-FieldNum "CmdId.PlayerLoginFinishScRsp")
$DummyMap[ (Get-FieldNum "CmdId.SceneEntityMoveCsReq") ] = (Get-FieldNum "CmdId.SceneEntityMoveScRsp")

$gameserver = [TcpListener]::new(
    [IPAddress]::Parse("127.0.0.1"),
    23301
)
$gameserver.Start()
Write-Host "gameserver @ http://localhost:23301/"

while ($true) {
    $client = $gameserver.AcceptTcpClient()
    Write-Host "new client:" $client.Client.RemoteEndPoint
    try {
        $stream = $client.GetStream()
        while ($true) {
            $packet = $null
            if (-not $client.Connected -or -not $stream.CanRead) {
                break
            }
            try {
                $packet = [Packet]::read_packet($stream)
            }
            catch {
                Write-Host "error reading packet: $($_.Exception.Message)"
                break
            }
            if ($null -eq $packet) { break }
            Write-Host "got cmd" $packet.cmd
            if ($DummyMap.ContainsKey($packet.cmd)) {
                $rsp_cmd = $DummyMap[$packet.cmd]
                $packet = [Packet]::new([uint16]$rsp_cmd, [byte[]]@(), [byte[]]@())
                $encoded = $packet.encode()
                $stream.Write($encoded, 0, $encoded.Length)
                Write-Host "dummy'd" $packet.cmd
            }
            else {
                Write-Host "handled" $packet.cmd
            }
        }
    }
    finally {
        Write-Host "client disconnected"
    }
}
