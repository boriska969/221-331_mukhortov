param()
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$source = Get-Content -LiteralPath (Join-Path $root 'stage1\table_app.c') -Raw
$block = [regex]::Match($source, '(?s)kTable\[\]\s*=\s*\{(.*?)\};').Groups[1].Value
$rows = @([regex]::Matches($block, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
if ($rows.Count -ne 5) { throw 'Expected 5 reference records' }
$results = [Collections.Generic.List[object]]::new()
$log = [Collections.Generic.List[string]]::new()
foreach ($exeName in @('table_app.exe','app.exe')) {
    $exe = Join-Path $root ('build\bin\' + $exeName)
    $cases = @()
    for ($i=0; $i -lt $rows.Count; $i++) { $cases += @{Args=@([string]$i); Code=0; Text=('row {0}: {1}' -f $i,$rows[$i])} }
    foreach ($bad in @('-1','5','9','abc','1x','2147483648','-2147483649','99999999999999999999999999')) {
        $cases += @{Args=@($bad); Code=1; Text='WARNING:'}
    }
    $cases += @{Args=@(); Code=1; Text='usage:'}
    $cases += @{Args=@('0','1'); Code=1; Text='usage:'}
    foreach ($case in $cases) {
        $arguments = $case.Args
        $actual = (& $exe @arguments 2>&1 | Out-String).Trim()
        $code = $LASTEXITCODE
        $passed = $code -eq $case.Code -and $actual.Contains($case.Text)
        $label = $exeName + ' ' + ($arguments -join ' ')
        $log.Add('> ' + $label); $log.Add($actual); $log.Add(('exit={0}; {1}' -f $code, $(if ($passed) {'PASS'} else {'FAIL'})))
        $results.Add([pscustomobject]@{program=$exeName; arguments=($arguments -join ' '); exit=$code; passed=$passed; output=$actual})
        if (-not $passed) { throw ('Test failed: ' + $label + ' / ' + $actual) }
    }
}
$log.Add(('PASS: {0}/{0} runtime checks' -f $results.Count))
$log | Set-Content -LiteralPath (Join-Path $root 'analysis\logs\runtime_tests.txt') -Encoding utf8
$results | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'analysis\logs\runtime_tests.json') -Encoding utf8
$binaryLog = [Collections.Generic.List[string]]::new()
$binaryResults = @()
foreach ($fileName in @('table_app.exe','app.exe','Enclave.signed.dll')) {
    $file = Join-Path $root ('build\bin\' + $fileName)
    $data = [IO.File]::ReadAllBytes($file)
    $text = [Text.Encoding]::ASCII.GetString($data)
    $binaryLog.Add($fileName + ' SHA256=' + (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash)
    foreach ($row in $rows) {
        foreach ($needle in @($row) + @($row.Split(';'))) {
            $offset = $text.IndexOf($needle, [StringComparison]::Ordinal)
            $result = [pscustomobject]@{file=$fileName; text=$needle; offset=$offset; hex=$(if($offset -ge 0){'0x{0:X8}' -f $offset}else{'NOT FOUND'})}
            $binaryResults += $result
            $binaryLog.Add(('{0}: {1}' -f $result.hex,$needle))
            if (($fileName -eq 'app.exe' -and $offset -ge 0) -or ($fileName -ne 'app.exe' -and $offset -lt 0)) { throw 'Unexpected binary-string result' }
        }
    }
    if ($fileName -eq 'Enclave.signed.dll') {
        $start = [Math]::Max(0, ($text.IndexOf($rows[0]) -band -16) - 48)
        $end = [Math]::Min($data.Length, ($text.IndexOf($rows[-1]) -band -16) + 96)
        $dump = [Collections.Generic.List[string]]::new()
        $dump.Add('Enclave.signed.dll | file offset | hexadecimal bytes | ASCII')
        for ($offset=$start; $offset -lt $end; $offset+=16) {
            $chunk=$data[$offset..([Math]::Min($offset+15,$data.Length-1))]
            $hex=($chunk | ForEach-Object {$_.ToString('X2')}) -join ' '
            $ascii= -join ($chunk | ForEach-Object {if($_ -ge 32 -and $_ -le 126){[char]$_}else{'.'}})
            $dump.Add(('{0:X8}  {1,-47}  {2}' -f $offset,$hex,$ascii))
        }
        $dump | Set-Content -LiteralPath (Join-Path $root 'analysis\logs\enclave_hex.txt') -Encoding utf8
    }
}
$binaryLog | Set-Content -LiteralPath (Join-Path $root 'analysis\logs\binary_strings.txt') -Encoding utf8
$binaryResults | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'analysis\logs\binary_strings.json') -Encoding utf8
$log[-1]
'PASS: plaintext is present in table_app.exe and Enclave.signed.dll; absent from app.exe'
