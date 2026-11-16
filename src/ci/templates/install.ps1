# The reviewed workflow supplies the expected digest and source identity.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-PSDebug -Off
$complete = $false
$created = $false
$client = $null
$handler = $null
$cancellation = $null
$MaxBytes = 536870912L
function Require([bool] $Condition, [string] $Message) {
    if (-not $Condition) { throw $Message }
}
function Safe-Name([string] $Name) {
    Require ($Name.Length -gt 0 -and $Name.Length -le 240 -and $Name -cmatch '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$') 'Unsafe archive member path'
    foreach ($segment in $Name.Split('/')) {
        Require ($segment -ne '.' -and $segment -ne '..') 'Unsafe archive member path'
    }
}
function Remember([string] $Name, [bool] $Directory) {
    Require ($seen.Add($Name)) 'Duplicate or case-colliding archive member'
    $prefix = $Name
    while ($prefix.Contains('/')) { $prefix = $prefix.Substring(0, $prefix.LastIndexOf('/')); Require (-not $seenFiles.Contains($prefix)) 'Archive file and directory paths conflict' }
    if (-not $Directory) {
        foreach ($previous in $seen) { Require (-not $previous.StartsWith("$Name/", [StringComparison]::OrdinalIgnoreCase)) 'Archive file and directory paths conflict' }
        [void]$seenFiles.Add($Name)
    }
}
function Read-At([System.IO.FileStream] $Stream, [long] $Offset, [int] $Length) {
    Require ($Offset -ge 0 -and $Offset + $Length -le $Stream.Length) 'Truncated archive record'
    $Stream.Position = $Offset
    $buffer = [byte[]]::new($Length)
    $read = 0
    while ($read -lt $Length) {
        $amount = $Stream.Read($buffer, $read, $Length - $read)
        Require ($amount -gt 0) 'Truncated archive record'
        $read += $amount
    }
    return ,$buffer
}
function U16([byte[]] $Bytes, [int] $Offset) { return [BitConverter]::ToUInt16($Bytes, $Offset) }
function U32([byte[]] $Bytes, [int] $Offset) { return [long][BitConverter]::ToUInt32($Bytes, $Offset) }
function Ascii([byte[]] $Bytes, [int] $Offset, [int] $Length, [bool] $Padded) {
    $builder = [System.Text.StringBuilder]::new()
    $ended = $false
    for ($i = $Offset; $i -lt $Offset + $Length; $i++) {
        $byte = $Bytes[$i]
        if ($Padded -and $byte -eq 0) { $ended = $true; continue }
        Require (-not $ended -and $byte -ge 32 -and $byte -le 126) 'Invalid archive text field'
        [void]$builder.Append([char]$byte)
    }
    return $builder.ToString()
}
function Octal([byte[]] $Bytes, [int] $Offset, [int] $Length) {
    $value = 0L; $ended = $false
    for ($i = $Offset; $i -lt $Offset + $Length; $i++) {
        $byte = $Bytes[$i]
        if ($byte -eq 0 -or $byte -eq 32) { $ended = $true; continue }
        Require (-not $ended -and $byte -ge 48 -and $byte -le 55) 'Unsupported tar numeric field'
        $value = $value * 8 + $byte - 48
        Require ($value -le $MaxBytes) 'Archive entry size limit exceeded'
    }
    return $value
}
function Copy-Bounded([System.IO.Stream] $InputStream, [System.IO.Stream] $OutputStream, [long] $Limit) {
    $buffer = [byte[]]::new(65536)
    $total = 0L
    while (($read = $InputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $total += $read
        Require ($total -le $Limit) 'Expanded or downloaded size limit exceeded'
        $OutputStream.Write($buffer, 0, $read)
    }
    return $total
}
function Zip-Extras([System.IO.FileStream] $Stream, [long] $Offset, [int] $Length) {
    $end = $Offset + $Length
    $seen = [System.Collections.Generic.HashSet[int]]::new()
    while ($Offset -lt $end) {
        Require ($Offset + 4 -le $end) 'Truncated ZIP extra field'
        $b = Read-At $Stream $Offset 4
        $id = U16 $b 0; $amount = U16 $b 2
        Require ($id -in @(21589, 30837, 22613, 10)) 'Unsupported ZIP extra field'
        Require ($seen.Add($id)) 'Duplicate ZIP extra field'
        $Offset += 4 + $amount
        Require ($Offset -le $end) 'Truncated ZIP extra payload'
    }
}
function Pax-Metadata([byte[]] $Bytes, [bool] $Local) {
    $position = 0
    $metadata = @{}
    while ($position -lt $Bytes.Length) {
        $cursor = $position; $length = 0; $digits = 0
        while ($cursor -lt $Bytes.Length -and $Bytes[$cursor] -ne 32) {
            $byte = $Bytes[$cursor]
            Require ($byte -ge 48 -and $byte -le 57 -and $digits -lt 6) 'Invalid PAX length'
            $length = $length * 10 + $byte - 48; $digits++; $cursor++
        }
        Require ($digits -gt 0 -and $length -gt $digits + 3 -and $position + $length -le $Bytes.Length -and $Bytes[$position + $length - 1] -eq 10) 'Invalid PAX record'
        $keyStart = $cursor + 1; $equals = $keyStart
        while ($equals -lt $position + $length - 1 -and $Bytes[$equals] -ne 61) { $equals++ }
        Require ($equals -gt $keyStart -and $equals -lt $position + $length - 1) 'Invalid PAX key'
        $key = Ascii $Bytes $keyStart ($equals - $keyStart) $false
        Require (-not $metadata.ContainsKey($key)) 'Duplicate PAX key'
        if ($key.StartsWith('SCHILY.xattr.', [StringComparison]::Ordinal) -or $key.StartsWith('LIBARCHIVE.xattr.', [StringComparison]::Ordinal)) { $metadata[$key] = ''; $position += $length; continue }
        $value = Ascii $Bytes ($equals + 1) ($position + $length - $equals - 2) $false
        switch -CaseSensitive ($key) {
            'path' { Require $Local 'Global PAX path forbidden'; Safe-Name $value.TrimEnd('/') }
            'size' { Require ($Local -and $value -cmatch '^[0-9]{1,9}$' -and [long]$value -le $MaxBytes) 'Invalid PAX size' }
            { $_ -cin @('mtime', 'atime', 'ctime', 'uid', 'gid', 'uname', 'gname', 'SCHILY.fflags') } { }
            default { throw 'Unsupported PAX attribute' }
        }
        $metadata[$key] = $value
        $position += $length
    }
    return $metadata
}
try {
    Require ($PSVersionTable.PSVersion.Major -ge 7 -and $IsWindows) 'Windows PowerShell 7 or later is required'
    Require ($env:RELSHIP_SHA256 -cmatch '^[0-9a-fA-F]{64}$') 'Invalid expected digest'
    Require ($env:RELSHIP_SOURCE_ID -cmatch '^[0-9a-fA-F]{64}$') 'Invalid expected source identity'
    Require ($env:RELSHIP_VERSION -cmatch '^[A-Za-z0-9][A-Za-z0-9.+-]{0,127}$') 'Invalid expected version'
    Require ($env:RELSHIP_FORMAT -cin @('binary', 'tar.gz', 'zip')) 'Unsupported archive format'
    $uri = [Uri]::new($env:RELSHIP_URL, [UriKind]::Absolute)
    Require ($uri.Scheme -ceq 'https' -and [string]::IsNullOrEmpty($uri.UserInfo)) 'HTTPS URL without credentials required'
    $token = $env:RELSHIP_DOWNLOAD_TOKEN
    Require ([string]::IsNullOrEmpty($token) -or $token -cmatch '^[A-Za-z0-9._~+/-]+=*$') 'Invalid bearer token'
    $installDirectory = $env:RELSHIP_INSTALL_DIR
    Require (-not [string]::IsNullOrEmpty($installDirectory) -and [IO.Path]::IsPathFullyQualified($installDirectory) -and $installDirectory -notmatch '[\r\n]') 'Absolute private install directory required'
    Require (-not [IO.Directory]::Exists($installDirectory) -and -not [IO.File]::Exists($installDirectory)) 'Install directory already exists'
    # Restrict access to the runner identity at creation, without inherited ACL grants.
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $security.AddAccessRule($rule)
    [System.IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($installDirectory), $security)
    $created = $true
    $download = [IO.Path]::Combine($installDirectory, 'download')
    $installed = [IO.Path]::Combine($installDirectory, 'relship.exe')
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(180)
    $cancellation = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(180))
    $redirects = 0
    while ($true) {
        Require ($uri.Scheme -ceq 'https' -and [string]::IsNullOrEmpty($uri.UserInfo)) 'Unsafe HTTPS redirect'
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $uri)
        if (-not [string]::IsNullOrEmpty($token)) { $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token) }
        $response = $null
        try {
            $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancellation.Token).GetAwaiter().GetResult()
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                Require ([string]::IsNullOrEmpty($token) -and $redirects -lt 3 -and $null -ne $response.Headers.Location) 'Authenticated or excessive redirects forbidden'
                $uri = [Uri]::new($uri, $response.Headers.Location)
                $redirects++
                continue
            }
            Require ($status -eq 200) 'HTTPS download did not return status 200'
            Require ($null -eq $response.Content.Headers.ContentLength -or $response.Content.Headers.ContentLength -le $MaxBytes) 'Download size limit exceeded'
            $inputStream = $response.Content.ReadAsStreamAsync($cancellation.Token).GetAwaiter().GetResult()
            $outputStream = [IO.File]::Open($download, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            try {
                $buffer = [byte[]]::new(65536); $total = 0L
                while (($read = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token).GetAwaiter().GetResult()) -gt 0) {
                    $total += $read; Require ($total -le $MaxBytes) 'Download size limit exceeded'
                    $outputStream.Write($buffer, 0, $read)
                }
                Require ($total -gt 0) 'Empty engine download'
            } finally { $outputStream.Dispose(); $inputStream.Dispose() }
            break
        } finally { if ($null -ne $response) { $response.Dispose() }; $request.Dispose() }
    }
    $token = $null
    Remove-Item Env:RELSHIP_DOWNLOAD_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:RELSHIP_URL -ErrorAction SilentlyContinue
    $hash = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
    Require ($hash -ieq $env:RELSHIP_SHA256) 'Download SHA-256 mismatch'
    if ($env:RELSHIP_FORMAT -ceq 'binary') {
        Require ([string]::IsNullOrEmpty($env:RELSHIP_MEMBER)) 'Binary downloads cannot declare a member'
        [IO.File]::Move($download, $installed)
    } else {
        $member = $env:RELSHIP_MEMBER
        Safe-Name $member
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $seenFiles = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $found = $false
        if ($env:RELSHIP_FORMAT -ceq 'tar.gz') {
            $archivePath = [IO.Path]::Combine($installDirectory, 'archive')
            $compressedStream = [IO.File]::OpenRead($download)
            $gzip = [IO.Compression.GZipStream]::new($compressedStream, [IO.Compression.CompressionMode]::Decompress)
            $expandedStream = [IO.File]::Open($archivePath, [IO.FileMode]::CreateNew)
            try { $expanded = Copy-Bounded $gzip $expandedStream $MaxBytes } finally { $expandedStream.Dispose(); $gzip.Dispose(); $compressedStream.Dispose() }
            Require ($expanded % 512 -eq 0) 'Invalid tar archive length'
            $archive = [IO.File]::OpenRead($archivePath)
            try {
                $offset = 0L; $count = 0; $selectedOffset = 0L; $selectedSize = 0L; $pending = $false; $pax = @{}
                while ($offset + 512 -le $expanded) {
                    $b = Read-At $archive $offset 512
                    $sum = 0; foreach ($byte in $b) { $sum += $byte }
                    if ($sum -eq 0) {
                        Require (-not $pending -and $expanded - $offset -ge 1024) 'Missing tar end marker or orphan PAX header'
                        $archive.Position = $offset
                        $tail = [byte[]]::new(65536)
                        while (($read = $archive.Read($tail, 0, $tail.Length)) -gt 0) {
                            for ($i = 0; $i -lt $read; $i++) { Require ($tail[$i] -eq 0) 'Unexpected tar trailing data' }
                        }
                        break
                    }
                    $count++; Require ($count -le 1024) 'Too many archive members'
                    $checksum = Octal $b 148 8
                    for ($i = 148; $i -lt 156; $i++) { $sum += 32 - $b[$i] }
                    Require ($sum -eq $checksum -and (Ascii $b 257 5 $false) -ceq 'ustar') 'Invalid tar header or checksum'
                    $name = Ascii $b 0 100 $true
                    if ($b[262] -eq 0 -and $b[263] -eq 48 -and $b[264] -eq 48) {
                        $prefix = Ascii $b 345 155 $true
                        if ($prefix.Length -gt 0) { $name = "$prefix/$name" }
                    } else { Require ($b[262] -eq 32 -and $b[263] -eq 32 -and $b[264] -eq 0) 'Unsupported tar header' }
                    $kind = $b[156]; $entrySize = Octal $b 124 12
                    if ($kind -eq 76) {
                        Require ($name -ceq '././@LongLink' -and -not $pending -and $entrySize -gt 1 -and $entrySize -le 242) 'Invalid GNU long-name header'
                        $longName = Read-At $archive ($offset + 512) ([int]$entrySize)
                        Require ($longName[$longName.Length - 1] -eq 0) 'Unterminated GNU long name'
                        $value = Ascii $longName 0 $longName.Length $true; Safe-Name $value.TrimEnd('/')
                        $pax = @{ path = $value }; $pending = $true
                        $offset += 512 + [long][Math]::Ceiling($entrySize / 512.0) * 512
                        continue
                    }
                    if ($kind -eq 120 -or $kind -eq 103) {
                        if ($name -cne '././@PaxHeader') { Safe-Name $name }
                        Require (-not $pending -and $entrySize -le 65536) 'Ambiguous or oversized PAX headers'
                        $metadata = Read-At $archive ($offset + 512) ([int]$entrySize)
                        $values = Pax-Metadata $metadata ($kind -eq 120)
                        if ($kind -eq 120) { $pending = $true; $pax = $values }
                        $offset += 512 + [long][Math]::Ceiling($entrySize / 512.0) * 512
                        continue
                    }
                    Require ($kind -in @(0, 48, 53)) 'Non-regular tar member'
                    Safe-Name $name.TrimEnd('/')
                    if ($pax.ContainsKey('path')) { $name = $pax['path'] }
                    Require (-not $pax.ContainsKey('size') -or [long]$pax['size'] -eq $entrySize) 'Ambiguous PAX size override'
                    $pax = @{}; $pending = $false
                    if ($kind -eq 53) { Require ($entrySize -eq 0) 'Nonempty tar directory'; $name = $name.TrimEnd('/') }
                    Safe-Name $name
                    Remember $name ($kind -eq 53)
                    $next = $offset + 512 + [long][Math]::Ceiling($entrySize / 512.0) * 512
                    Require ($next -le $expanded) 'Truncated tar member'
                    if ($name -ceq $member) { Require ($kind -ne 53 -and $entrySize -gt 0) 'Declared member is not a regular executable'; $found = $true; $selectedOffset = $offset + 512; $selectedSize = $entrySize }
                    $offset = $next
                }
                Require ($found -and $offset -lt $expanded) 'Declared tar member or end marker missing'
                $archive.Position = $selectedOffset
                $output = [IO.File]::Open($installed, [IO.FileMode]::CreateNew)
                try {
                    $buffer = [byte[]]::new(65536); $remaining = $selectedSize
                    while ($remaining -gt 0) { $read = $archive.Read($buffer, 0, [int][Math]::Min($remaining, $buffer.Length)); Require ($read -gt 0) 'Truncated tar executable'; $output.Write($buffer, 0, $read); $remaining -= $read }
                } finally { $output.Dispose() }
            } finally { $archive.Dispose() }
        } else {
            $archive = [IO.File]::OpenRead($download)
            try {
                $size = $archive.Length; $b = Read-At $archive ($size - 22) 22
                if ((U32 $b 0) -ne 101010256) {
                    $tailLength = [int][Math]::Min($size, 65557); $tail = Read-At $archive ($size - $tailLength) $tailLength
                    $candidate = -1
                    for ($i = 0; $i -le $tailLength - 22; $i++) {
                        if ($tail[$i] -eq 80 -and $tail[$i + 1] -eq 75 -and $tail[$i + 2] -eq 5 -and $tail[$i + 3] -eq 6 -and $i + 22 + (U16 $tail ($i + 20)) -eq $tailLength) {
                            Require ($candidate -eq -1) 'Ambiguous ZIP end records'; $candidate = $i
                        }
                    }
                    Require ($candidate -ge 0) 'Missing ZIP end record'
                    $b = Read-At $archive ($size - $tailLength + $candidate) 22
                }
                Require ((U32 $b 0) -eq 101010256 -and (U32 $b 4) -eq 0) 'Unsupported ZIP end record or multi-disk ZIP'
                $entries = U16 $b 8; $directorySize = U32 $b 12; $directory = U32 $b 16
                $archiveComment = U16 $b 20
                Require ($entries -gt 0 -and $entries -le 1024 -and (U16 $b 10) -eq $entries -and $directory + $directorySize + 22 + $archiveComment -eq $size) 'Unsupported ZIP layout'
                $cursor = $directory; $physical = 0L; $total = 0L; $selectedSize = 0L; $selectedCrc = 0L
                for ($index = 0; $index -lt $entries; $index++) {
                    $b = Read-At $archive $cursor 46
                    Require ((U32 $b 0) -eq 33639248 -and (U16 $b 6) -le 20) 'Unsupported ZIP directory record'
                    $creator = U16 $b 4; $flags = U16 $b 8; $method = U16 $b 10
                    Require (($flags -band (-bnot 2062)) -eq 0 -and $method -in @(0, 8) -and ($method -eq 8 -or ($flags -band 6) -eq 0)) 'Unsupported ZIP flags or compression'
                    $crc = U32 $b 16; $compressed = U32 $b 20; $entrySize = U32 $b 24
                    $length = U16 $b 28; $extra = U16 $b 30; $comment = U16 $b 32; $disk = U16 $b 34
                    $attributes = U32 $b 38; $localOffset = U32 $b 42
                    Require ($length -gt 0 -and $length -le 241 -and $extra -le 4096 -and $disk -eq 0 -and $localOffset -eq $physical) 'Unsupported or ambiguous ZIP metadata'
                    $total += $entrySize; Require ($total -le $MaxBytes -and $compressed -le $MaxBytes) 'ZIP expanded size limit exceeded'
                    $nameBytes = Read-At $archive ($cursor + 46) $length; $name = Ascii $nameBytes 0 $length $false
                    $isDirectory = $name.EndsWith('/')
                    $mode = ($attributes -shr 16) -band 61440; $creatorHost = $creator -shr 8
                    if ($creatorHost -eq 3) { Require (($isDirectory -and $mode -eq 16384) -or (-not $isDirectory -and $mode -eq 32768)) 'Non-regular ZIP member' }
                    elseif ($creatorHost -eq 0) { Require (($attributes -band (-bnot 63)) -eq 0 -and ($attributes -band 8) -eq 0 -and (($attributes -band 16) -ne 0) -eq $isDirectory) 'Unsupported DOS ZIP attributes' }
                    else { throw 'Unsupported ZIP creator platform' }
                    Require (-not $isDirectory -or $entrySize -eq 0) 'Nonempty ZIP directory'
                    Safe-Name $name.TrimEnd('/'); Remember $name.TrimEnd('/') $isDirectory
                    Zip-Extras $archive ($cursor + 46 + $length) $extra
                    $b = Read-At $archive $physical 30
                    Require ((U32 $b 0) -eq 67324752 -and (U16 $b 4) -le 20 -and (U16 $b 6) -eq $flags -and (U16 $b 8) -eq $method) 'ZIP local header mismatch'
                    $descriptor = ($flags -band 8) -ne 0
                    Require (((U32 $b 14) -eq $crc -or ($descriptor -and (U32 $b 14) -eq 0)) -and ((U32 $b 18) -eq $compressed -or ($descriptor -and (U32 $b 18) -eq 0)) -and ((U32 $b 22) -eq $entrySize -or ($descriptor -and (U32 $b 22) -eq 0)) -and (U16 $b 26) -eq $length) 'ZIP local checksum or size mismatch'
                    $localExtra = U16 $b 28; Require ($localExtra -le 4096) 'Oversized ZIP local extra metadata'
                    $localName = Read-At $archive ($physical + 30) $length; Require ((Ascii $localName 0 $length $false) -ceq $name) 'ZIP local and directory names differ'
                    Zip-Extras $archive ($physical + 30 + $length) $localExtra
                    $physical += 30 + $length + $localExtra + $compressed
                    if ($descriptor) {
                        $b = Read-At $archive $physical 4
                        if ((U32 $b 0) -eq 134695760) { $physical += 4 }
                        $b = Read-At $archive $physical 12
                        Require ((U32 $b 0) -eq $crc -and (U32 $b 4) -eq $compressed -and (U32 $b 8) -eq $entrySize) 'ZIP data descriptor mismatch'
                        $physical += 12
                    }
                    Require ($physical -le $directory) 'ZIP members overlap directory'
                    $cursor += 46 + $length + $extra + $comment
                    if ($name -ceq $member) { Require (-not $isDirectory -and $entrySize -gt 0) 'Declared member is not a regular executable'; $found = $true; $selectedSize = $entrySize; $selectedCrc = $crc }
                }
                Require ($cursor -eq $directory + $directorySize -and $physical -eq $directory -and $found) 'ZIP layout or declared member mismatch'
                $archive.Position = 0
                $zip = [IO.Compression.ZipArchive]::new($archive, [IO.Compression.ZipArchiveMode]::Read, $true)
                try {
                    $entry = $zip.GetEntry($member)
                    Require ($null -ne $entry -and $entry.Length -eq $selectedSize) 'ZIP executable metadata mismatch'
                    $entryStream = $entry.Open(); $output = [IO.File]::Open($installed, [IO.FileMode]::CreateNew)
                    try { $written = Copy-Bounded $entryStream $output $selectedSize; Require ($written -eq $selectedSize) 'ZIP executable expanded size mismatch' } finally { $output.Dispose(); $entryStream.Dispose() }
                } finally { $zip.Dispose() }
                # Older .NET versions do not verify an entry CRC while reading.
                Add-Type -TypeDefinition @'
using System;
using System.IO;
public static class RelshipBootstrapCrc32 {
    public static uint Compute(string path) {
        var table = new uint[256];
        for (uint i = 0; i < table.Length; i++) {
            uint item = i;
            for (int bit = 0; bit < 8; bit++) item = (item & 1) != 0 ? (item >> 1) ^ 0xedb88320U : item >> 1;
            table[i] = item;
        }
        uint crc = 0xffffffffU;
        using (var stream = File.OpenRead(path)) {
            var buffer = new byte[65536];
            int count;
            while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
                for (int i = 0; i < count; i++) crc = table[(crc ^ buffer[i]) & 255] ^ (crc >> 8);
        }
        return crc ^ 0xffffffffU;
    }
}
'@
                Require ([long][RelshipBootstrapCrc32]::Compute($installed) -eq $selectedCrc) 'ZIP executable CRC-32 mismatch'
            } finally { $archive.Dispose() }
        }
    }
    # Expected values are checked by the digest-verified executable before any job uses it.
    & $installed build-info --json --expect-version $env:RELSHIP_VERSION --expect-source-id $env:RELSHIP_SOURCE_ID --expect-contract 1 *> $null
    Require ($LASTEXITCODE -eq 0) 'Installed engine build identity mismatch'
    if (-not [string]::IsNullOrEmpty($env:GITHUB_ENV)) { [IO.File]::AppendAllText($env:GITHUB_ENV, "RELSHIP_BIN=$installed`n", [Text.UTF8Encoding]::new($false)) }
    else { [Console]::WriteLine($installed) }
    $complete = $true
} catch {
    # HttpClient exceptions can include signed URLs; never print exception payloads.
    [Console]::Error.WriteLine('relship bootstrap: installation failed; verify the reviewed profile, native capabilities, and HTTPS artifact')
    exit 1
} finally {
    if ($null -ne $cancellation) { $cancellation.Dispose() }
    if ($null -ne $client) { $client.Dispose() }
    if ($null -ne $handler) { $handler.Dispose() }
    if ($created) {
        if ($complete) {
            foreach ($name in @('download', 'archive')) { $path = [IO.Path]::Combine($installDirectory, $name); if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) } }
        } else { [IO.Directory]::Delete($installDirectory, $true) }
    }
}
