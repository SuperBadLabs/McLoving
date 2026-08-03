param(
    [Parameter(Mandatory = $true)]
    [string]$SourceRoot,
    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,
    [Parameter(Mandatory = $true)]
    [string]$SourceCommit,
    [Parameter(Mandatory = $true)]
    [string]$SourceTree,
    [string]$Toolchain = "1.97.1"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Assert-AuthenticodeValid([string]$Path, [string]$Thumbprint) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid") {
        throw "Authenticode verification failed for ${Path}: $($signature.Status) $($signature.StatusMessage)"
    }
    if ($signature.SignerCertificate.Thumbprint -ne $Thumbprint) {
        throw "unexpected Authenticode signer for $Path"
    }
    return $signature
}

function New-RestrictedDirectoryAcl {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $administrators = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl.SetOwner($administrators)
    foreach ($sidValue in @("S-1-5-18", "S-1-5-32-544")) {
        $sid = [Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

if (Test-Path -LiteralPath $OutputRoot) {
    throw "refusing to overwrite existing package root: $OutputRoot"
}
if ($SourceCommit -notmatch "^[0-9a-f]{40}$") {
    throw "source commit must be an exact lowercase 40-hex object id"
}
if ($SourceTree -notmatch "^[0-9a-f]{40}$") {
    throw "source tree must be an exact lowercase 40-hex object id"
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Windows package qualification requires an elevated administrator session"
}

$source = (Resolve-Path -LiteralPath $SourceRoot).Path
$gitRoot = (& git -C $source rev-parse --show-toplevel) -join "`n"
if ($LASTEXITCODE -ne 0) {
    throw "source root is not a Git worktree: $source"
}
$gitRoot = (Resolve-Path -LiteralPath $gitRoot.Trim()).Path
if (-not [string]::Equals($gitRoot, $source, [StringComparison]::OrdinalIgnoreCase)) {
    throw "source root must be the Git worktree root: expected $gitRoot, received $source"
}
$actualCommit = ((& git -C $source rev-parse --verify HEAD) -join "").Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0) {
    throw "failed to resolve source commit"
}
$actualTree = ((& git -C $source rev-parse --verify 'HEAD^{tree}') -join "").Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0) {
    throw "failed to resolve source tree"
}
if ($actualCommit -ne $SourceCommit) {
    throw "source commit mismatch: expected $SourceCommit, actual $actualCommit"
}
if ($actualTree -ne $SourceTree) {
    throw "source tree mismatch: expected $SourceTree, actual $actualTree"
}
$dirtyPaths = @(& git -C $source status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
    throw "failed to inspect source worktree status"
}
if ($dirtyPaths.Count -ne 0) {
    throw "source worktree must be clean before package qualification"
}

$outputParent = Split-Path -Parent $OutputRoot
New-Item -ItemType Directory -Force -Path $outputParent | Out-Null
New-Item -ItemType Directory -Path $OutputRoot | Out-Null
Set-Acl -LiteralPath $OutputRoot -AclObject (New-RestrictedDirectoryAcl)
$package = Join-Path $OutputRoot "package"
New-Item -ItemType Directory -Path $package | Out-Null
$snapshotArchive = Join-Path $OutputRoot "source-tree.tar"
$snapshot = Join-Path $OutputRoot "source"
& git -C $source archive --format=tar --output=$snapshotArchive $SourceTree
if ($LASTEXITCODE -ne 0) { throw "immutable source export failed: $LASTEXITCODE" }
New-Item -ItemType Directory -Path $snapshot | Out-Null
& tar.exe -xf $snapshotArchive -C $snapshot
if ($LASTEXITCODE -ne 0) { throw "immutable source extraction failed: $LASTEXITCODE" }
Remove-Item -LiteralPath $snapshotArchive -Force
$buildTarget = Join-Path $OutputRoot "cargo-target"
$previousCargoTargetDir = $env:CARGO_TARGET_DIR
$env:CARGO_TARGET_DIR = $buildTarget

Push-Location $snapshot
try {
    $rustc = (& rustup run $Toolchain rustc -Vv) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "pinned rustc query failed: $LASTEXITCODE" }
    & rustup run $Toolchain cargo build --locked --release -p mcloving-agent `
        --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "release agent build failed: $LASTEXITCODE" }
    & rustup run $Toolchain cargo metadata --locked --format-version 1 |
        Set-Content -Encoding utf8 (Join-Path $package "cargo-metadata.json")
    if ($LASTEXITCODE -ne 0) { throw "locked dependency inventory failed: $LASTEXITCODE" }
    Copy-Item -LiteralPath (Join-Path $snapshot "Cargo.lock") `
        -Destination (Join-Path $package "Cargo.lock")
} finally {
    Pop-Location
    if ($null -eq $previousCargoTargetDir) {
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
    } else {
        $env:CARGO_TARGET_DIR = $previousCargoTargetDir
    }
    if (Test-Path -LiteralPath $snapshotArchive) {
        Remove-Item -LiteralPath $snapshotArchive -Force
    }
    if (Test-Path -LiteralPath $snapshot) {
        Remove-Item -LiteralPath $snapshot -Recurse -Force
    }
}

$builtBinary = Join-Path $buildTarget "x86_64-pc-windows-msvc\release\mcloving-agent.exe"
$packagedBinary = Join-Path $package "mcloving-agent.exe"
Copy-Item -LiteralPath $builtBinary -Destination $packagedBinary
Remove-Item -LiteralPath $buildTarget -Recurse -Force
$unsignedBinarySha256 = Get-Sha256 $packagedBinary

$subject = "CN=McLoving WIN-003 qualification $SourceCommit"
$certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $subject `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddDays(7)
$packageFailure = $null
$certificateCleanupFailures = @()
try {
    $certificatePath = Join-Path $OutputRoot "win003-signer.cer"
    Export-Certificate -Cert $certificate -FilePath $certificatePath | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $certificatePath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

    $binarySignature = Set-AuthenticodeSignature `
        -LiteralPath $packagedBinary `
        -Certificate $certificate `
        -HashAlgorithm SHA256
    if ($binarySignature.Status -ne "Valid") {
        throw "agent signing failed: $($binarySignature.Status) $($binarySignature.StatusMessage)"
    }
    Assert-AuthenticodeValid $packagedBinary $certificate.Thumbprint | Out-Null
    $signedBinarySha256 = Get-Sha256 $packagedBinary

    $inventory = Get-ChildItem -LiteralPath $package -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                path = $_.FullName.Substring($package.Length + 1).Replace("\", "/")
                bytes = $_.Length
                sha256 = Get-Sha256 $_.FullName
            }
        }
    $receipt = [ordered]@{
        schema = "mcloving-win-003-package-v1"
        qualification = "persistent-host-test"
        production_release_provenance = $false
        source_commit = $SourceCommit
        source_tree = $SourceTree
        source_snapshot = "git archive --format=tar <source_tree>"
        rust_toolchain = $Toolchain
        rustc = $rustc
        target = "x86_64-pc-windows-msvc"
        build_command = "cd <immutable-source-snapshot>; CARGO_TARGET_DIR=<package-root>/cargo-target rustup run $Toolchain cargo build --locked --release -p mcloving-agent --target x86_64-pc-windows-msvc"
        unsigned_binary_sha256 = $unsignedBinarySha256
        signed_binary_sha256 = $signedBinarySha256
        signer_subject = $certificate.Subject
        signer_thumbprint = $certificate.Thumbprint.ToLowerInvariant()
        signer_public_certificate_sha256 = Get-Sha256 $certificatePath
        files = @($inventory)
    }
    $receiptPath = Join-Path $package "PACKAGE-RECEIPT.json"
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 $receiptPath

    $manifestPath = Join-Path $package "SHA256SUMS"
    Get-ChildItem -LiteralPath $package -File -Recurse |
        Where-Object { $_.FullName -ne $manifestPath } |
        Sort-Object FullName |
        ForEach-Object {
            "$(Get-Sha256 $_.FullName)  $($_.FullName.Substring($package.Length + 1).Replace('\', '/'))"
        } | Set-Content -Encoding ascii $manifestPath

    $archivePath = Join-Path $OutputRoot "mcloving-agent-win003.zip"
    Compress-Archive -Path (Join-Path $package "*") -DestinationPath $archivePath -CompressionLevel Optimal
    $archiveSha256 = Get-Sha256 $archivePath
    $envelopePath = Join-Path $OutputRoot "PACKAGE-SIGNATURE.ps1"
    @"
`$PackageArchiveSha256 = '$archiveSha256'
`$SourceCommit = '$SourceCommit'
`$SourceTree = '$SourceTree'
"@ | Set-Content -Encoding utf8 $envelopePath
    $envelopeSignature = Set-AuthenticodeSignature `
        -LiteralPath $envelopePath `
        -Certificate $certificate `
        -HashAlgorithm SHA256
    if ($envelopeSignature.Status -ne "Valid") {
        throw "package envelope signing failed: $($envelopeSignature.Status) $($envelopeSignature.StatusMessage)"
    }
    Assert-AuthenticodeValid $envelopePath $certificate.Thumbprint | Out-Null

    $closure = [ordered]@{
        schema = "mcloving-win-003-package-closure-v1"
        archive = Split-Path -Leaf $archivePath
        archive_sha256 = $archiveSha256
        envelope = Split-Path -Leaf $envelopePath
        envelope_sha256 = Get-Sha256 $envelopePath
        binary_sha256 = $signedBinarySha256
        signer_thumbprint = $certificate.Thumbprint.ToLowerInvariant()
        authenticode_binary = "Valid"
        authenticode_envelope = "Valid"
        private_key_exportable = $false
        result = "PASS"
    }
    $closure | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $OutputRoot "PACKAGE-CLOSURE.json")
} catch {
    $packageFailure = $_
} finally {
    foreach ($storeName in @("My", "Root", "CA", "TrustedPublisher")) {
        try {
            Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $certificate.Thumbprint } |
                Remove-Item -Force -ErrorAction Stop
            $residualCertificate = Get-ChildItem "Cert:\LocalMachine\$storeName" -ErrorAction Stop |
                Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }
            if ($residualCertificate) {
                throw "qualification certificate remains in $storeName after cleanup"
            }
        } catch {
            $certificateCleanupFailures += "${storeName}: $($_.Exception.Message)"
        }
    }
}
if ($packageFailure) {
    if ($certificateCleanupFailures.Count -ne 0) {
        throw "package operation failed: $($packageFailure.Exception.Message); certificate cleanup failed: $($certificateCleanupFailures -join '; ')"
    }
    throw $packageFailure
}
if ($certificateCleanupFailures.Count -ne 0) {
    throw "certificate cleanup failed: $($certificateCleanupFailures -join '; ')"
}
