#requires -Version 5.1
<#
GCP single-project read-only evidence collector for Windows PowerShell 5.1+.
No API enablement, no cloud resource modifications, no secret-value retrieval.
Run from a trusted Windows workstation with gcloud authenticated.

Collector 2.2.5 emits schema assessment-expanded-2.2 (CloSec analyzer adapter
gcp-expanded-2.2-adapter-1). Corrections over the 2.1 HostFix build:
  * every gcloud command is bounded by -CommandTimeoutSeconds and its process tree is
    terminated on expiry (TIMEOUT), instead of an unbounded WaitForExit();
  * REST calls retry 429/5xx/transport timeouts a bounded number of times, refresh an
    expired token once, stop on repeated page tokens and enforce -PageHardCap;
  * a 200 response lacking the expected list property is UNEXPECTED_SCHEMA, not EMPTY;
    responses reporting unreachable locations are PARTIAL;
  * 403 SERVICE_DISABLED is API_DISABLED and quota-project / serviceusage.services.use
    failures are QUOTA_PROJECT_DENIED instead of generic ACCESS_DENIED;
  * Discovery Engine requests are resource-type aware: dataStores and engines are read
    through the location's endpoint ({location}-discoveryengine for us/eu), listed per
    discovered location, and unsupported resource types are recorded without requests;
  * optional -QuotaProject, used only after typed confirmation and recorded in the manifest;
  * outputs are written atomically, the manifest is written even when interrupted, and
    checksums.sha256 covers every evidence file; 2.2.4 lists only the project's own images; 2.2.5 fixes Run/Functions IAM arguments.
  2.2.6: API-key and bucket detail loops read arrays without PowerShell 5.1 collapse; Run/Functions IAM
    falls back to the gcloud lists when the REST lists fail (recorded in dependency_fallbacks); gcloud
    failures are classified as RATE_LIMITED / AUTH_ERROR / SERVER_ERROR with anchored 403/404 matching
    and bounded read-only retries for transient failures; gcloud output is read as UTF-8; the ZIP is
    built with explicit forward-slash entry names and its SHA-256 is printed and written beside it;
    detail limits reached are recorded in detail_limits_reached. Evidence format unchanged (2.2).
  2.2.7: identity/governance/security APIs are always attempted (the enabled-services list is
    context only for them); effective org policies are described for bare, constraints/ and
    policies/ names plus a fixed baseline; a 'service disabled' message naming another project
    number is QUOTA_PROJECT_DENIED; no dependency fallback is recorded for an API_DISABLED list;
    'argument --x: Must be specified' is COMMAND_ERROR. Evidence format unchanged (2.2).
  2.2.8: custom role details pass the bare role ID with --project/--organization (gcloud rejects
    a projects/ or organizations/ prefix); unrecognised names are skipped with a console note;
    gcloud's 'role id should not include any' message is COMMAND_ERROR. Evidence format unchanged (2.2).
#>
[CmdletBinding()]
param(
    # Default (empty): organization\projects.json and projects\ beside this script.
    [string]$ProjectsFile = '', [string]$OutputRoot = '',
    # 0 means no collector-imposed detail-item limit.
    [int]$MaxDetailItems = 0,
    # 0 means follow pagination until the API stops returning nextPageToken.
    [int]$MaxApiPages = 0,
    [int]$HttpTimeoutSeconds = 45,
    # Bound for each gcloud command; an expired command is terminated and recorded as TIMEOUT.
    [int]$CommandTimeoutSeconds = 300,
    # Bounded retries for HTTP 429/5xx and transport timeouts (exponential backoff, max 30 s).
    [int]$HttpMaxRetries = 3,
    # Absolute page ceiling used when MaxApiPages is 0, so no listing can loop forever.
    [int]$PageHardCap = 2000,
    # Optional, explicitly approved quota/billing project for user credentials. Never
    # inferred or switched automatically; requires typed confirmation; recorded in manifest.
    [string]$QuotaProject = '',
    # Off by default (2.2.3): folder/organization-wide IAM searches return IAM bindings of
    # every project in that scope. Use only when the engagement authorizes org-level review;
    # requires typed confirmation. CloSec keeps only the collected project's results.
    [switch]$IncludeOrganizationSearch
)
$CollectorVersion = '2.2.8'
$SchemaVersion = 'assessment-expanded-2.2'
if ($CommandTimeoutSeconds -lt 10 -or $CommandTimeoutSeconds -gt 3600) { throw 'CommandTimeoutSeconds must be between 10 and 3600.' }
if ($HttpMaxRetries -lt 0 -or $HttpMaxRetries -gt 6) { throw 'HttpMaxRetries must be between 0 and 6.' }
if ($PageHardCap -lt 1 -or $PageHardCap -gt 100000) { throw 'PageHardCap must be between 1 and 100000.' }
if ($QuotaProject -and $QuotaProject -notmatch '^[a-z][a-z0-9-]{4,28}[a-z0-9]$') { throw 'QuotaProject is not a valid project ID.' }
$ErrorActionPreference = 'Stop'
if (-not $ProjectsFile) { $ProjectsFile = Join-Path $PSScriptRoot 'organization\projects.json' }; if (-not $OutputRoot) { $OutputRoot = Join-Path $PSScriptRoot 'projects' }

# Resolve the Windows batch launcher explicitly. `Get-Command gcloud` may return
# gcloud.ps1, which cannot be launched directly by ProcessStartInfo on Windows.
$gcloudCmd = Get-Command 'gcloud.cmd' -CommandType Application -ErrorAction SilentlyContinue
if (-not $gcloudCmd) {
    $gcloudCmd = Get-Command 'gcloud.bat' -CommandType Application -ErrorAction SilentlyContinue
}
if (-not $gcloudCmd) {
    throw 'Cannot locate gcloud.cmd or gcloud.bat in PATH. Run `Get-Command gcloud -All` and check the Google Cloud SDK bin directory.'
}
$GcloudLauncher = $gcloudCmd.Source
Write-Host "Using Windows gcloud launcher: $GcloudLauncher" -ForegroundColor Cyan
# 2.2.6: gcloud (Python) writes UTF-8 when told to; decode its pipes as UTF-8 so non-ASCII
# project, resource and label names are not mangled by the console code page.
function Set-Utf8Process([System.Diagnostics.ProcessStartInfo]$StartInfo) {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $StartInfo.StandardOutputEncoding = $utf8NoBom
    $StartInfo.StandardErrorEncoding = $utf8NoBom
    $StartInfo.EnvironmentVariables['PYTHONIOENCODING'] = 'utf-8'
    $StartInfo.EnvironmentVariables['PYTHONUTF8'] = '1'
}
# Read-only project discovery: used when the inventory file is missing or is not JSON
# (for example table output from `gcloud projects list` without --format=json).
function Get-DiscoveredProjects {
    Write-Host 'Discovering accessible projects (gcloud projects list, read-only)...' -ForegroundColor Cyan
    $savedEncoding = [Console]::OutputEncoding; $savedIo = $env:PYTHONIOENCODING; $savedUtf8 = $env:PYTHONUTF8
    try {
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
        $env:PYTHONIOENCODING = 'utf-8'; $env:PYTHONUTF8 = '1'
        $text = (& $GcloudLauncher projects list --format=json --quiet 2>$null) -join "`n"
    } finally {
        [Console]::OutputEncoding = $savedEncoding; $env:PYTHONIOENCODING = $savedIo; $env:PYTHONUTF8 = $savedUtf8
    }
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($text)) {
        throw 'Project discovery failed. Run `gcloud auth login` and confirm resourcemanager.projects.list access.'
    }
    $folder = Split-Path -Parent $ProjectsFile
    if ($folder -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($ProjectsFile, $text, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Project inventory saved: $ProjectsFile" -ForegroundColor Green
    return $text
}

# ConvertFrom-Json may enumerate arrays through the PowerShell pipeline. Explicitly
# distinguish a top-level array from an optional {"projects": [...]} wrapper.
if (Test-Path -LiteralPath $ProjectsFile -PathType Leaf) {
    $jsonText = [System.IO.File]::ReadAllText($ProjectsFile, [System.Text.Encoding]::UTF8)
} else {
    Write-Host "Project inventory not found: $ProjectsFile" -ForegroundColor Yellow
    $jsonText = Get-DiscoveredProjects
}
try {
    $parsed = ConvertFrom-Json -InputObject $jsonText -ErrorAction Stop
} catch {
    Write-Host "Project inventory is not JSON ($($_.Exception.Message)); rediscovering." -ForegroundColor Yellow
    try {
        $parsed = ConvertFrom-Json -InputObject (Get-DiscoveredProjects) -ErrorAction Stop
    } catch {
        throw "Could not parse project inventory: $($_.Exception.Message)"
    }
}
$records = @()
if ($null -ne $parsed) {
    if ($parsed -is [array]) {
        $records = @($parsed)
    } elseif ($parsed.PSObject.Properties.Name -contains 'projects') {
        $records = @($parsed.projects)
    } else {
        $records = @($parsed)
    }
}
$projects = @($records | Where-Object {
    $null -ne $_ -and
    ($_.PSObject.Properties.Name -contains 'projectId') -and
    -not [string]::IsNullOrWhiteSpace([string]$_.projectId)
})
if ($projects.Count -eq 0) {
    throw "No projectId records found in $ProjectsFile. Check JSON structure."
}
Write-Host "`nProjects loaded: $($projects.Count)" -ForegroundColor Green
for ($i = 0; $i -lt $projects.Count; $i++) {
    Write-Host ('{0,3}. {1} | {2} | {3}' -f ($i + 1), [string]$projects[$i].name, [string]$projects[$i].projectId, [string]$projects[$i].projectNumber)
}
$choice = Read-Host 'Enter the list number of the project to assess'
$selection = 0
if (-not [int]::TryParse($choice, [ref]$selection)) { throw 'Selection must be a number.' }
if ($selection -lt 1 -or $selection -gt $projects.Count) { throw 'Selection outside available project list.' }
$project = $projects[$selection - 1]
$ProjectId = [string]$project.projectId
# 2.2.7: the target's project number distinguishes a disabled service in the target project
# from one in the quota project. Empty when it cannot be resolved (then API_DISABLED is kept).
$TargetProjectNumber = ''
if ([string]$project.projectNumber -match '^\d{1,20}$') { $TargetProjectNumber = [string]$project.projectNumber }
$pname = [string]$project.name
Write-Host "`nSelected project: $pname ($ProjectId)" -ForegroundColor Yellow
if ((Read-Host 'Type YES to collect read-only metadata for this project') -cne 'YES') {
    Write-Host 'Cancelled; no collection performed.'
    return
}
if ($IncludeOrganizationSearch) {
    Write-Host 'Organization-wide IAM search requested: folder and organization searches return IAM bindings of other projects.' -ForegroundColor Yellow
    if ((Read-Host 'Type ORG to confirm org-level review is authorized') -cne 'ORG') {
        Write-Host 'Organization-wide search not confirmed; no collection performed.'
        return
    }
}
if ($QuotaProject) {
    Write-Host "Quota project requested: $QuotaProject. API quota and billing attribution will use this project." -ForegroundColor Yellow
    if ((Read-Host "Type $QuotaProject to confirm this approved quota project") -cne $QuotaProject) {
        Write-Host 'Quota project not confirmed; no collection performed.'
        return
    }
}

# Sign-in check (2.2.2). Collection runs gcloud non-interactively (--quiet), so an expired
# or reauthentication-required session would otherwise fail every dataset. This uses the
# same cmd.exe launcher as the REST token request; the token is discarded, never stored.
function Test-GcloudSession {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/d /s /c ""' + $GcloudLauncher + '" auth print-access-token --quiet"'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    Set-Utf8Process $psi
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit(90000)) {
        try { & taskkill.exe /PID $proc.Id /T /F 2>$null | Out-Null } catch {}
        return 'gcloud did not return an access token within 90 seconds.'
    }
    $token = [string]($outTask.GetAwaiter().GetResult().Trim() -split "`r?`n" | Select-Object -First 1)
    $stderrText = [string]$errTask.GetAwaiter().GetResult()
    $valid = ($proc.ExitCode -eq 0 -and $token -match '^[A-Za-z0-9._~+/-]{30,}$')
    $token = $null
    if ($valid) { return '' }
    $reason = (@($stderrText -split "`r?`n" | Where-Object { $_ -match '\S' } | Select-Object -First 2) -join ' ')
    if (-not $reason) { $reason = "gcloud exited with code $($proc.ExitCode)." }
    return $reason
}
Write-Host "`nChecking gcloud sign-in (read-only token check)..." -ForegroundColor Cyan
$sessionProblem = Test-GcloudSession
if ($sessionProblem) {
    Write-Host "gcloud sign-in check failed: $sessionProblem" -ForegroundColor Red
    Write-Host 'The gcloud session has expired or needs reauthentication. No collection was performed.' -ForegroundColor Red
    Write-Host 'Fix: run  gcloud auth login  (complete the browser sign-in), then run this collector again.' -ForegroundColor Yellow
    throw 'gcloud sign-in required before collection (run gcloud auth login).'
}
Write-Host 'gcloud sign-in check passed.' -ForegroundColor Green

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$safeName = $pname -replace '[^a-zA-Z0-9_-]', '_'
if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'project' }
$safeId = $ProjectId -replace '[^a-zA-Z0-9_-]', '_'
$root = Join-Path $OutputRoot "${safeName}__${safeId}__${stamp}"
New-Item -ItemType Directory -Path $root -Force | Out-Null
$manifest = New-Object 'System.Collections.Generic.List[object]'
$MaxDetailItems = [Math]::Max(0, $MaxDetailItems)
$MaxApiPages = [Math]::Max(0, $MaxApiPages)
$CollectionStatus = 'INTERRUPTED'

function Write-AtomicText([string]$Path, [string]$Text) {
    $temp = "$Path.partial"
    [System.IO.File]::WriteAllText($temp, $Text, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temp -Destination $Path -Force
}
function Stop-ProcessTree([int]$ProcessId) {
    # cmd.exe launches gcloud's Python child; terminate the whole tree, not only cmd.exe.
    try { & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null } catch {}
    try { Get-Process -Id $ProcessId -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } catch {}
}
function Add-ManifestEntry([string]$Domain, [string]$Dataset, [string]$Status, [string]$RequiredApi, [string]$Command) {
    $now = (Get-Date).ToUniversalTime().ToString('o')
    [void]$manifest.Add([pscustomobject]@{
        domain=$Domain; dataset=$Dataset; status=$Status; record_count=$null; exit_code=$null;
        started_utc=$now; finished_utc=$now; file=$null; error_file=$null;
        required_api=$RequiredApi; command=$Command
    })
}

# 2.2.6: classify a failed gcloud command from its stderr. Status codes are matched only next
# to an HTTP/status/code/error token, a reason phrase or brackets, so a bare 403/404 inside a
# resource name or unrelated text is not misread. Every status is a collection gap, never a result.
# 2.2.7: a 'service disabled' error names the project whose service is disabled. When that is
# not the target project (user credentials bill a quota project), it is QUOTA_PROJECT_DENIED.
$script:ClassificationNote = ''
$script:RestNote = ''
function Resolve-DisabledService([string]$Text) {
    $script:ClassificationNote = ''
    $named = [regex]::Match($Text, '(?i)(?:in project|on project|projects/|project \[|project_number:)\s*\[?(\d{6,20})')
    if (-not $named.Success) { return 'API_DISABLED' }
    if (-not $TargetProjectNumber) {
        $script:ClassificationNote = 'Target project number unresolved; the disabled service could belong to the quota project. Kept API_DISABLED.'
        return 'API_DISABLED'
    }
    if ($named.Groups[1].Value -ne $TargetProjectNumber) {
        $script:ClassificationNote = 'The disabled service belongs to another project (the quota/billing project), not the target project.'
        return 'QUOTA_PROJECT_DENIED'
    }
    return 'API_DISABLED'
}
function Get-GcloudFailureStatus([string]$Text) {
    $script:ClassificationNote = ''
    if ($Text -match '(?i)(has not been used.*disabled|API.*disabled|SERVICE_DISABLED|not enabled on project)') { return (Resolve-DisabledService $Text) }
    if ($Text -match '(?i)(quota project|USER_PROJECT_DENIED|serviceusage\.services\.use)') { return 'QUOTA_PROJECT_DENIED' }
    if ($Text -match '(?i)(Reauthentication|gcloud auth login|refreshing your current auth tokens|invalid_grant|invalid authentication credentials|UNAUTHENTICATED)') { return 'AUTH_ERROR' }
    if ($Text -match '(?i)(RESOURCE_EXHAUSTED|Quota exceeded|rateLimitExceeded|Too Many Requests|(?:HTTP(?:Error)?|status|code|error)[\s:=\[\(''"]*429\b|\b429\s*:|\[429\])') { return 'RATE_LIMITED' }
    if ($Text -match '(?i)(PERMISSION_DENIED|permission|not authorized|access denied|(?:HTTP(?:Error)?|status|code|error)[\s:=\[\(''"]*403\b|\b403\s*(?:Forbidden|:)|\[403\])') { return 'ACCESS_DENIED' }
    if ($Text -match '(?i)(NOT_FOUND|was not found|(?:HTTP(?:Error)?|status|code|error)[\s:=\[\(''"]*404\b|\b404\s*(?:Not Found|:)|\[404\])') { return 'NOT_FOUND' }
    if ($Text -match '(?-i:\bUNAVAILABLE\b|\bINTERNAL\b)|(?i:backendError|Service Unavailable|Bad Gateway|(?:HTTP(?:Error)?|status|code|error)[\s:=\[\(''"]*50[0234]\b|\[50[0234]\])') { return 'SERVER_ERROR' }
    if ($Text -match '(?i)(Invalid choice|unrecognized arguments|Invalid command|argument --[\w-]+: Must be specified|role id should not include any)') { return 'COMMAND_ERROR' }
    return 'FAILED'
}
# Only rate limiting and server-side transient errors are retried; the command is re-run unchanged
# (the same read-only list/describe/get-iam-policy call), never altered.
$GcloudTransientRetries = 3
function Test-TransientStatus([string]$Status) { return ($Status -eq 'RATE_LIMITED' -or $Status -eq 'SERVER_ERROR') }

# 2.2.7: the enabled-services list decides whether to call only for resource services. These
# identity, governance and security APIs are always attempted (some answer even when absent
# from the list) and classified from the response.
$PrecheckExempt = @('iam.googleapis.com','orgpolicy.googleapis.com','recommender.googleapis.com','accesscontextmanager.googleapis.com','securitycenter.googleapis.com','cloudasset.googleapis.com','logging.googleapis.com')
function Test-PrecheckSkip([string]$RequiredApi) {
    return [bool]($RequiredApi -and $EnabledApisKnown -and -not $EnabledApis.ContainsKey($RequiredApi) -and ($PrecheckExempt -notcontains $RequiredApi))
}

function Invoke-Collection {
    param([string]$Domain, [string]$Dataset, [string[]]$GcloudArgs, [string]$RequiredApi = '')
    $folder = Join-Path $root $Domain
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $outFile = Join-Path $folder "$Dataset.json"
    $errFile = Join-Path $folder "$Dataset.stderr.txt"
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $status = 'FAILED'; $recordCount = $null; $exitCode = $null
    Write-Host "[$Domain] $Dataset"
    if (Test-PrecheckSkip $RequiredApi) {
        [void]$manifest.Add([pscustomobject]@{
            domain=$Domain; dataset=$Dataset; status='API_DISABLED'; record_count=$null;
            exit_code=$null; started_utc=$started; finished_utc=(Get-Date).ToUniversalTime().ToString('o');
            file=$null; error_file=$null; required_api=$RequiredApi;
            command=('gcloud ' + ($GcloudArgs -join ' ') + ' --format=json --quiet')
        })
        return
    }
    try {
        # PowerShell 5.1 may turn native stderr into terminating errors under Stop.
        # Redirect stdout/stderr to separate local temporary files using Start-Process.
        $tempOut = Join-Path $folder "$Dataset.stdout.tmp"
        $tempErr = Join-Path $folder "$Dataset.stderr.tmp"
        $allArgs = @($GcloudArgs) + @('--format=json', '--quiet')
        if ($QuotaProject) { $allArgs += "--billing-project=$QuotaProject" }
        $gcloudPath = $GcloudLauncher
        # Avoid cmd.exe string construction: Start-Process handles .cmd via cmd /c.
        # Inputs are from a trusted inventory and fixed command definitions.
        function Quote-Arg([string]$value) {
            if ($value -match '[\r\n"%!]') { throw 'Unsafe character in CLI argument.' }
            if ($value -match '[&|<>^]') { throw 'Shell metacharacter in CLI argument.' }
            return '"' + $value + '"'
        }
        $quoted = ($allArgs | ForEach-Object { Quote-Arg ([string]$_) }) -join ' '
        $retryNotes = New-Object 'System.Collections.Generic.List[string]'
        $attempt = 0
        while ($true) {
            $attempt++
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            if ($gcloudPath -match '\.(cmd|bat)$') {
                $psi.FileName = $env:ComSpec
                $psi.Arguments = '/d /s /c ""' + $gcloudPath + '" ' + $quoted + '"'
            } else {
                $psi.FileName = $gcloudPath
                $psi.Arguments = $quoted
            }
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            Set-Utf8Process $psi
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            [void]$process.Start()
            $outTask = $process.StandardOutput.ReadToEndAsync()
            $errTask = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit($CommandTimeoutSeconds * 1000)) {
                Stop-ProcessTree $process.Id
                $status = 'TIMEOUT'
                throw "gcloud exceeded $CommandTimeoutSeconds seconds and was terminated"
            }
            $process.WaitForExit()  # bounded exit observed; flush the asynchronous readers
            $stdout = $outTask.GetAwaiter().GetResult()
            $stderr = $errTask.GetAwaiter().GetResult()
            $exitCode = $process.ExitCode
            if ($exitCode -eq 0) { break }
            $status = Get-GcloudFailureStatus $stderr
            if ($script:ClassificationNote) { [void]$retryNotes.Add($script:ClassificationNote) }
            if ((Test-TransientStatus $status) -and $attempt -le $GcloudTransientRetries) {
                $wait = [int][Math]::Min(30, [Math]::Pow(2, $attempt))
                [void]$retryNotes.Add("Attempt $attempt failed ($status); retrying the same read-only command in $wait s.")
                Start-Sleep -Seconds $wait
                continue
            }
            break
        }
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        if ($retryNotes.Count -gt 0) {
            $stderr = (($retryNotes.ToArray()) -join "`n") + "`n" + [string]$stderr
        }
        if (-not [string]::IsNullOrWhiteSpace($stderr)) {
            [System.IO.File]::WriteAllText($errFile, $stderr, $utf8)
        }
        if ($exitCode -ne 0) {
            throw "gcloud exited with code $exitCode after $attempt attempt(s)"
        }
        $status = 'FAILED'  # success after a retry clears the earlier transient status
        if ([string]::IsNullOrWhiteSpace($stdout)) { $status = 'INVALID_OUTPUT'; throw 'No JSON output returned.' }
        try { $obj = ConvertFrom-Json -InputObject $stdout -ErrorAction Stop }
        catch { $status = 'INVALID_OUTPUT'; throw }
        Write-AtomicText $outFile $stdout
        if ($null -eq $obj) { $recordCount = 0 }
        elseif ($obj -is [array]) { $recordCount = $obj.Count }
        else { $recordCount = 1 }
        $status = if ($recordCount -eq 0) { 'EMPTY' } else { 'SUCCESS' }
    } catch {
        Add-Content -LiteralPath $errFile -Value ([string]$_) -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $outFile) { Remove-Item -LiteralPath $outFile -Force }
    } finally {
        foreach ($temp in @($tempOut, $tempErr)) {
            if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
        }
    }
    [void]$manifest.Add([pscustomobject]@{
        domain=$Domain; dataset=$Dataset; status=$status; record_count=$recordCount; required_api=$RequiredApi;
        exit_code=$exitCode; started_utc=$started;
        finished_utc=(Get-Date).ToUniversalTime().ToString('o');
        file=$(if (Test-Path -LiteralPath $outFile) { "$Domain/$Dataset.json" } else { $null });
        error_file=$(if (Test-Path -LiteralPath $errFile) { "$Domain/$Dataset.stderr.txt" } else { $null });
        command=('gcloud ' + ($GcloudArgs -join ' ') + ' --format=json --quiet')
    })
}
function Run([string]$Domain, [string]$Dataset, [string[]]$Arguments, [string]$RequiredApi = '') {
    Invoke-Collection -Domain $Domain -Dataset $Dataset -GcloudArgs $Arguments -RequiredApi $RequiredApi
}
$EnabledApis = @{}
$EnabledApisKnown = $false
# 2.2.6: detail loops record when -MaxDetailItems stopped them; dependency fallbacks are recorded,
# so evidence never disappears silently when a list it depends on failed.
$DetailLimits = [ordered]@{ service_accounts=$false; buckets=$false; api_keys=$false; custom_roles=$false; kms=$false }
$Fallbacks = New-Object 'System.Collections.Generic.List[object]'
function Get-ManifestStatus([string]$Domain, [string]$Dataset) {
    $found = 'NOT_ATTEMPTED'
    foreach ($entry in $manifest) { if ($entry.domain -eq $Domain -and $entry.dataset -eq $Dataset) { $found = [string]$entry.status } }
    return $found
}

try {
Run 'inventory' 'project' @('projects','describe',$ProjectId)
$describedFile = Join-Path $root 'inventory\project.json'
if (Test-Path -LiteralPath $describedFile) {
    try {
        $described = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($describedFile))
        if ([string]$described.projectNumber -match '^\d{1,20}$') { $TargetProjectNumber = [string]$described.projectNumber }
    } catch { }
}
Run 'inventory' 'assets' @('asset','search-all-resources',"--scope=projects/$ProjectId")
Run 'inventory' 'asset_iam_search' @('asset','search-all-iam-policies',"--scope=projects/$ProjectId")
# CAI asset list exposes resource and IAM snapshots beyond search summaries, when authorized.
Run 'inventory' 'asset_resource_list' @('asset','list',"--project=$ProjectId",'--content-type=resource')
Run 'inventory' 'asset_iam_list' @('asset','list',"--project=$ProjectId",'--content-type=iam-policy')
Run 'api' 'enabled_services' @('services','list','--enabled',"--project=$ProjectId")
$servicesFile = Join-Path $root 'api\enabled_services.json'
if (Test-Path -LiteralPath $servicesFile) {
    $servicesRaw = [System.IO.File]::ReadAllText($servicesFile, [System.Text.Encoding]::UTF8)
    $servicesParsed = ConvertFrom-Json -InputObject $servicesRaw -ErrorAction Stop
    foreach ($service in @($servicesParsed)) {
        if ($null -eq $service) { continue }
        $apiName = $null
        if ($null -ne $service.config -and $service.config.name) {
            $apiName = [string]$service.config.name
        } elseif ($service.name -match '/services/([^/]+)$') {
            $apiName = [string]$Matches[1]
        }
        if ($apiName) { $EnabledApis[$apiName] = $true }
    }
    $EnabledApisKnown = ($EnabledApis.Count -gt 0)
}
Write-Host "Enabled API inventory available: $EnabledApisKnown ($($EnabledApis.Count) APIs)"
# REST evidence collector: uses the current gcloud OAuth token in memory only.
# Never persists tokens, authorization headers, secret payloads or business data.
Add-Type -AssemblyName System.Net.Http
$RestSession = $null
function Initialize-RestSession {
    if ($null -ne $script:RestSession) { return $true }
    # Use the same Windows cmd.exe launcher as the working gcloud collectors.
    # The token stays in memory; it is never written to evidence or error files.
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:ComSpec
        $psi.Arguments = '/d /s /c ""' + $GcloudLauncher + '" auth print-access-token --quiet"'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        Set-Utf8Process $psi
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit(60000)) {
            Stop-ProcessTree $proc.Id
            return $false
        }
        $tokenText = $outTask.GetAwaiter().GetResult()
        [void]$errTask.GetAwaiter().GetResult()
        if ($proc.ExitCode -ne 0) { return $false }
        $token = [string]($tokenText.Trim() -split "`r?`n" | Select-Object -First 1)
        if ($token -notmatch '^[A-Za-z0-9._~+/-]{30,}$') { return $false }
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($HttpTimeoutSeconds)
        $client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $token)
        if ($QuotaProject) { [void]$client.DefaultRequestHeaders.Add('X-Goog-User-Project', $QuotaProject) }
        $script:RestSession = $client
        $token = $null; $tokenText = $null
        return $true
    } catch { return $false }
}
function Reset-RestSession {
    if ($null -ne $script:RestSession) { $script:RestSession.Dispose() }
    $script:RestSession = $null
}
function Get-HttpStatusCategory([int]$Code, [string]$Body) {
    if ($Code -eq -1) { return 'TIMEOUT' }
    if ($Code -eq -2) { return 'HTTP_ERROR' }
    if ($Code -eq 401) { return 'AUTH_ERROR' }
    if ($Code -eq 403) {
        if ($Body -match '(?i)(SERVICE_DISABLED|has not been used in project|it is disabled)') { return (Resolve-DisabledService $Body) }
        if ($Body -match '(?i)(quota project|USER_PROJECT_DENIED|serviceusage\.services\.use)') { return 'QUOTA_PROJECT_DENIED' }
        return 'ACCESS_DENIED'
    }
    if ($Code -eq 404) { return 'NOT_FOUND' }
    if ($Code -eq 429) { return 'RATE_LIMITED' }
    if ($Code -ge 500) { return 'SERVER_ERROR' }
    return 'HTTP_ERROR'
}
function Send-RestGet([string]$Url) {
    # Bounded retries; one token refresh on 401. Returns status code, body and reason.
    $attempt = 0; $refreshed = $false
    while ($true) {
        $attempt++
        $code = 0; $payload = ''; $reason = ''
        try {
            $response = $script:RestSession.GetAsync($Url).GetAwaiter().GetResult()
            $code = [int]$response.StatusCode
            $payload = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $reason = [string]$response.ReasonPhrase
            $response.Dispose()
        } catch {
            $inner = $_.Exception
            while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
            $code = if ($inner -is [System.Threading.Tasks.TaskCanceledException] -or $inner -is [System.TimeoutException]) { -1 } else { -2 }
            $reason = $inner.GetType().Name
        }
        if ($code -eq 401 -and -not $refreshed) {
            $refreshed = $true
            Reset-RestSession
            if (Initialize-RestSession) { continue }
        }
        $retryable = ($code -eq 429 -or $code -ge 500 -or $code -lt 0)
        if ($retryable -and $attempt -le $HttpMaxRetries) {
            Start-Sleep -Seconds ([int][Math]::Min(30, [Math]::Pow(2, $attempt)))
            continue
        }
        return [pscustomobject]@{ Code=$code; Body=$payload; Reason=$reason; Attempts=$attempt }
    }
}
# List envelopes Google APIs return alongside (or instead of) an empty list property.
$EnvelopeFields = @('nextPageToken','pageToken','unreachable','missingZones','failedLocations','kind','etag','selfLink','id','warning','totalSize')
function Invoke-RestEvidence {
    param([string]$Domain,[string]$Dataset,[string]$Url,[string]$RequiredApi='',
          [string]$ArrayField='', [bool]$Paginate=$false)
    $folder = Join-Path $root $Domain
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
    $outFile = Join-Path $folder "$Dataset.json"
    $errFile = Join-Path $folder "$Dataset.stderr.txt"
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $status='FAILED'; $count=$null; $pages=0; $errMessage=$null
    Write-Host "[$Domain REST] $Dataset"
    if (Test-PrecheckSkip $RequiredApi) {
        $status='API_DISABLED'
    } elseif (-not (Initialize-RestSession)) {
        $status='AUTH_ERROR'; $errMessage='Unable to obtain an OAuth access token from current gcloud session.'
    } else {
        try {
            $results = New-Object 'System.Collections.Generic.List[object]'
            $pageUrl = $Url
            $seenTokens = @{}
            $unreachable = $false
            $schemaIssue = $null
            $cap = if ($MaxApiPages -gt 0) { $MaxApiPages } else { $PageHardCap }
            do {
                if ($pages -ge $cap) { $status='TRUNCATED'; break }
                $response = Send-RestGet $pageUrl
                if ($response.Code -lt 200 -or $response.Code -ge 300) {
                    $status = Get-HttpStatusCategory $response.Code $response.Body
                    $script:RestNote = $script:ClassificationNote
                    $body = [string]$response.Body
                    # Error bodies can include project/resource names; never credentials.
                    throw "HTTP $($response.Code) - $($response.Reason) - attempts $($response.Attempts) - $($body.Substring(0,[Math]::Min(1600,$body.Length)))"
                }
                $body = ConvertFrom-Json -InputObject $response.Body -ErrorAction Stop
                $pages++
                if ($ArrayField) {
                    $prop=$body.PSObject.Properties[$ArrayField]
                    if ($null -ne $prop) {
                        if ($null -ne $prop.Value) { foreach ($item in @($prop.Value)) { [void]$results.Add($item) } }
                    } else {
                        $other = @($body.PSObject.Properties | ForEach-Object { $_.Name } | Where-Object { $EnvelopeFields -notcontains $_ })
                        if ($other.Count -gt 0) {
                            $schemaIssue = "Expected list property '$ArrayField' absent; observed properties: " + (($other | Select-Object -First 20) -join ',')
                        }
                    }
                } else { [void]$results.Add($body) }
                foreach ($u in @('unreachable','missingZones','failedLocations')) {
                    $p = $body.PSObject.Properties[$u]
                    if ($null -ne $p -and $null -ne $p.Value -and @($p.Value).Count -gt 0) { $unreachable = $true }
                }
                $next=$body.PSObject.Properties['nextPageToken']
                if ($null -eq $next) { $next=$body.PSObject.Properties['pageToken'] }
                $pageUrl=$null
                if ($Paginate -and $null -ne $next -and -not [string]::IsNullOrWhiteSpace([string]$next.Value)) {
                    $token = [string]$next.Value
                    if ($seenTokens.ContainsKey($token)) {
                        $status='TRUNCATED'; $errMessage='Pagination token repeated; listing stopped to avoid an unbounded loop.'
                        break
                    }
                    $seenTokens[$token] = $true
                    $separator=if ($Url.Contains('?')) {'&'} else {'?'}
                    $pageUrl=$Url+$separator+'pageToken='+[Uri]::EscapeDataString($token)
                }
            } while ($pageUrl)
            if ($schemaIssue) {
                $status='UNEXPECTED_SCHEMA'; $errMessage=$schemaIssue
            } else {
                $count=$results.Count
                Write-AtomicText $outFile (ConvertTo-Json -InputObject @($results.ToArray()) -Depth 80 -Compress)
                if ($status -ne 'TRUNCATED') {
                    $status = if ($unreachable) { 'PARTIAL' } elseif ($count -eq 0) { 'EMPTY' } else { 'SUCCESS' }
                }
                if ($unreachable) { $errMessage = 'Response reported unreachable locations; listing is incomplete.' }
            }
        } catch {
            $errMessage=[string]$_.Exception.Message
            if ($script:RestNote) { $errMessage = $script:RestNote + ' ' + $errMessage; $script:RestNote = '' }
            if ($status -in @('SUCCESS','EMPTY')) { $status='FAILED' }
            if ($status -eq 'FAILED' -and $errMessage -match '(?i)(Invalid JSON|Conversion from JSON failed|JSON primitive)') { $status='INVALID_OUTPUT' }
        }
    }
    if ($errMessage) { [System.IO.File]::WriteAllText($errFile,$errMessage,(New-Object System.Text.UTF8Encoding($false))) }
    [void]$manifest.Add([pscustomobject]@{
        domain=$Domain;dataset=$Dataset;status=$status;record_count=$count;pages=$pages;
        started_utc=$started;finished_utc=(Get-Date).ToUniversalTime().ToString('o');
        required_api=$RequiredApi;file=$(if(Test-Path $outFile){"$Domain/$Dataset.json"}else{$null});
        error_file=$(if(Test-Path $errFile){"$Domain/$Dataset.stderr.txt"}else{$null});
        command=('GET '+($Url -replace 'pageToken=[^&]+','pageToken=[REDACTED]'))
    })
}
function Safe-Name([string]$Value) { return ($Value -replace '[^a-zA-Z0-9_-]','_') }
function E([string]$v) { return [Uri]::EscapeDataString($v) }
function RestList([string]$d,[string]$n,[string]$url,[string]$api,[string]$field) {
    Invoke-RestEvidence $d $n $url $api $field $true
}
function Read-EvidenceArray([string]$RelativePath) {
    $file=Join-Path $root $RelativePath
    if (-not (Test-Path -LiteralPath $file)) { return @() }
    try {
        $raw=ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($file))
        if ($null -eq $raw) { return @() }
        if ($raw -is [array]) { foreach ($entry in $raw) { Write-Output -NoEnumerate $entry }; return }
        Write-Output -NoEnumerate $raw
    } catch { return @() }
}

Run 'api' 'api_keys' @('services','api-keys','list',"--project=$ProjectId") 'apikeys.googleapis.com'
Run 'identity' 'project_iam' @('projects','get-iam-policy',$ProjectId)
Run 'identity' 'service_accounts' @('iam','service-accounts','list',"--project=$ProjectId")
Run 'identity' 'custom_roles' @('iam','roles','list',"--project=$ProjectId")
Run 'governance' 'org_policies' @('org-policies','list',"--project=$ProjectId")
Run 'logging' 'sinks' @('logging','sinks','list',"--project=$ProjectId")
# Logging exclusions: the supported command is `gcloud logging exclusions list` on SDKs that include it;
# command availability is SDK-dependent and errors remain explicit in the manifest.
# Logging exclusions require a supported REST collector; do not execute an invalid gcloud command.
# Logging exclusions are not a top-level gcloud command. Collect sink and bucket metadata; exclusions need a separate API collector.
Run 'logging' 'buckets_global' @('logging','buckets','list',"--project=$ProjectId",'--location=global')
Run 'monitoring' 'alert_policies' @('monitoring','policies','list',"--project=$ProjectId") 'monitoring.googleapis.com'
Run 'network' 'vpcs' @('compute','networks','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'subnets' @('compute','networks','subnets','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'firewall_rules' @('compute','firewall-rules','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'firewall_policies' @('compute','network-firewall-policies','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'routes' @('compute','routes','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'addresses' @('compute','addresses','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'routers' @('compute','routers','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'forwarding_rules' @('compute','forwarding-rules','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'vpn_tunnels' @('compute','vpn-tunnels','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'compute' 'instances' @('compute','instances','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'compute' 'disks' @('compute','disks','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'compute' 'snapshots' @('compute','snapshots','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'compute' 'gke_clusters' @('container','clusters','list',"--project=$ProjectId") 'container.googleapis.com'
Run 'serverless' 'cloud_run' @('run','services','list',"--project=$ProjectId") 'run.googleapis.com'
Run 'serverless' 'functions' @('functions','list',"--project=$ProjectId") 'cloudfunctions.googleapis.com'
Run 'storage' 'buckets' @('storage','buckets','list',"--project=$ProjectId")
Run 'data' 'cloud_sql' @('sql','instances','list',"--project=$ProjectId") 'sqladmin.googleapis.com'
Run 'security' 'secrets' @('secrets','list',"--project=$ProjectId") 'secretmanager.googleapis.com'
Run 'devops' 'artifact_repositories' @('artifacts','repositories','list',"--project=$ProjectId",'--location=all') 'artifactregistry.googleapis.com'

# Additional service-level inventory. Each operation is read-only and API-aware.
Run 'identity' 'workload_identity_pools' @('iam','workload-identity-pools','list',"--project=$ProjectId",'--location=global') 'iam.googleapis.com'
# KMS key rings are regional; location-specific discovery is not assumed here.
Run 'security' 'scc_findings' @('scc','findings','list',"projects/$ProjectId") 'securitycenter.googleapis.com'
Run 'network' 'dns_managed_zones' @('dns','managed-zones','list',"--project=$ProjectId") 'dns.googleapis.com'
Run 'compute' 'mig_managed' @('compute','instance-groups','managed','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'serverless' 'cloud_run_jobs' @('run','jobs','list',"--project=$ProjectId") 'run.googleapis.com'
# Scheduler jobs are regional; avoid falsely treating one region as complete coverage.
Run 'messaging' 'pubsub_topics' @('pubsub','topics','list',"--project=$ProjectId") 'pubsub.googleapis.com'
Run 'messaging' 'pubsub_subscriptions' @('pubsub','subscriptions','list',"--project=$ProjectId") 'pubsub.googleapis.com'
Run 'data' 'spanner_instances' @('spanner','instances','list',"--project=$ProjectId") 'spanner.googleapis.com'
# Memorystore instances are regional; use CAI for broad discovery.
Run 'devops' 'cloudbuild_triggers' @('builds','triggers','list',"--project=$ProjectId") 'cloudbuild.googleapis.com'
# Cloud Build connections are regional; use CAI for broad discovery.

# Additional project-level security configuration evidence (metadata only).
Run 'logging' 'settings' @('logging','settings','describe',"--project=$ProjectId") 'logging.googleapis.com'
Run 'logging' 'log_metrics' @('logging','metrics','list',"--project=$ProjectId") 'logging.googleapis.com'
Run 'logging' 'buckets_us_central1' @('logging','buckets','list',"--project=$ProjectId",'--location=us-central1') 'logging.googleapis.com'
Run 'logging' 'buckets_europe_west1' @('logging','buckets','list',"--project=$ProjectId",'--location=europe-west1') 'logging.googleapis.com'
Run 'network' 'ssl_policies' @('compute','ssl-policies','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'backend_services' @('compute','backend-services','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'url_maps' @('compute','url-maps','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'network' 'security_policies' @('compute','security-policies','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'compute' 'instance_templates' @('compute','instance-templates','list',"--project=$ProjectId") 'compute.googleapis.com'
Run 'compute' 'images' @('compute','images','list',"--project=$ProjectId",'--no-standard-images') 'compute.googleapis.com'

# Best-effort parent policy collection (project's immediate parent only).
# Parent metadata is already in the user's projects.json; no org-wide enumeration.
if ($project.parent -and $project.parent.type -and $project.parent.id) {
    $parentType = [string]$project.parent.type
    $parentId = [string]$project.parent.id
    if ($parentType -eq 'organization') {
        Run 'governance' 'parent_org_iam' @('organizations','get-iam-policy',$parentId)
        Run 'governance' 'parent_org_policies' @('org-policies','list',"--organization=$parentId")
    } elseif ($parentType -eq 'folder') {
        Run 'governance' 'parent_folder_iam' @('resource-manager','folders','get-iam-policy',$parentId)
        Run 'governance' 'parent_folder_policies' @('org-policies','list',"--folder=$parentId")
    }
}

# Collect API key restriction metadata, never key strings.
# 2.2.6: Read-EvidenceArray keeps a JSON array as separate items under PowerShell 5.1.
$keys = @(Read-EvidenceArray 'api/api_keys.json')
$i = 0
foreach ($key in $keys) {
    if ($null -eq $key -or [string]::IsNullOrWhiteSpace([string]$key.name)) { continue }
    if ($MaxDetailItems -gt 0 -and $i -ge $MaxDetailItems) { $DetailLimits['api_keys'] = $true; break }
    $i++
    Run 'api' "api_key_detail_$i" @('services','api-keys','describe',([string]$key.name),"--project=$ProjectId")
}
# Explicit array normalization: PowerShell 5.1's pipeline/array unrolling must not
# concatenate multiple service-account emails into one gcloud argument.
$saFile = Join-Path $root 'identity\service_accounts.json'
if (Test-Path -LiteralPath $saFile) {
    $saJson = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($saFile))
    $saRecords = @()
    if ($saJson -is [array]) { $saRecords = $saJson }
    elseif ($null -ne $saJson) { $saRecords = @($saJson) }
    $i = 0
    foreach ($sa in $saRecords) {
        if ($null -eq $sa -or [string]::IsNullOrWhiteSpace([string]$sa.email)) { continue }
        if ($MaxDetailItems -gt 0 -and $i -ge $MaxDetailItems) { $DetailLimits['service_accounts'] = $true; break }
        $i++
        $email = [string]$sa.email
        if ($email -match '[\s,;]') { throw "Invalid service-account identifier in evidence inventory: $email" }
        Run 'identity' "sa_keys_$i" @('iam','service-accounts','keys','list',"--iam-account=$email","--project=$ProjectId")
        Run 'identity' "sa_iam_$i" @('iam','service-accounts','get-iam-policy',$email,"--project=$ProjectId")
    }
}
$buckets = @(Read-EvidenceArray 'storage/buckets.json')
$i = 0
foreach ($bucket in $buckets) {
    if ($null -eq $bucket -or [string]::IsNullOrWhiteSpace([string]$bucket.name)) { continue }
    if ($MaxDetailItems -gt 0 -and $i -ge $MaxDetailItems) { $DetailLimits['buckets'] = $true; break }
    $i++
    $uri = 'gs://' + [string]$bucket.name
    Run 'storage' "bucket_iam_$i" @('storage','buckets','get-iam-policy',$uri)
    Run 'storage' "bucket_details_$i" @('storage','buckets','describe',$uri)
}

# Additional security-critical control plane evidence; best-effort, no IAM changes.
Run 'identity' 'service_account_keys_inventory' @('iam','service-accounts','list',"--project=$ProjectId") 'iam.googleapis.com'
Run 'governance' 'project_org_policy_v2' @('org-policies','list',"--project=$ProjectId") 'orgpolicy.googleapis.com'
Run 'security' 'kms_locations' @('kms','locations','list',"--project=$ProjectId") 'cloudkms.googleapis.com'

# Supported REST endpoints fill CLI gaps and permit regional discovery from CAI metadata.
$projectNumber = [string]$project.projectNumber
$baseLogging='https://logging.googleapis.com/v2/projects/'+[Uri]::EscapeDataString($ProjectId)
Invoke-RestEvidence 'logging' 'exclusions' ($baseLogging+'/exclusions?pageSize=1000') 'logging.googleapis.com' 'exclusions' $true
Invoke-RestEvidence 'logging' 'log_buckets_locations' ('https://logging.googleapis.com/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/locations/-/buckets?pageSize=1000') 'logging.googleapis.com' 'buckets' $true
Invoke-RestEvidence 'logging' 'logging_settings_rest' ($baseLogging+'/settings') 'logging.googleapis.com'
Invoke-RestEvidence 'api' 'api_keys_rest' ('https://apikeys.googleapis.com/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/locations/global/keys?pageSize=1000') 'apikeys.googleapis.com' 'keys' $true
Invoke-RestEvidence 'data' 'bigquery_datasets_rest' ('https://bigquery.googleapis.com/bigquery/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/datasets?all=true&maxResults=1000') 'bigquery.googleapis.com' 'datasets' $true

# BigQuery dataset access controls, table metadata and external connections (no rows).
$bqDatasets = @(Read-EvidenceArray 'data\bigquery_datasets_rest.json')
$detailIndex=0
foreach ($dataset in $bqDatasets) {
    if ($MaxDetailItems -gt 0 -and $detailIndex -ge $MaxDetailItems) { break }
    if ($null -eq $dataset.datasetReference -or -not $dataset.datasetReference.datasetId) { continue }
    $detailIndex++
    $datasetId=[string]$dataset.datasetReference.datasetId
    $safe=Safe-Name $datasetId
    $url='https://bigquery.googleapis.com/bigquery/v2/projects/'+[Uri]::EscapeDataString($ProjectId)+'/datasets/'+[Uri]::EscapeDataString($datasetId)
    Invoke-RestEvidence 'data' "bq_dataset_${safe}_details" $url 'bigquery.googleapis.com'
    Invoke-RestEvidence 'data' "bq_dataset_${safe}_tables" ($url+'/tables?maxResults=1000') 'bigquery.googleapis.com' 'tables' $true
}

# Discovery Engine, resource-type aware. Cloud Asset Inventory names identify projects,
# locations and resource types. Only dataStores and engines have v1 GET methods; they are
# read through the location's endpoint (global, or {location}-discoveryengine for us/eu).
# Child resources resolve to their parent; other types are recorded, never requested.
$assets = @(Read-EvidenceArray 'inventory\assets.json')
$discoveryNames = New-Object 'System.Collections.Generic.HashSet[string]'
$discoveryLocations = New-Object 'System.Collections.Generic.HashSet[string]'
$discoveryUnsupported = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($asset in $assets) {
    if ($null -eq $asset -or -not $asset.name) { continue }
    $name=[string]$asset.name
    if ($name -notmatch '^//discoveryengine\.googleapis\.com/(projects/([^/]+)/locations/([a-z0-9-]{1,40})/(.+))$') { continue }
    $full=$Matches[1]; $proj=$Matches[2]; $loc=$Matches[3]; $rest=$Matches[4]
    [void]$discoveryLocations.Add("$proj|$loc")
    if ($rest -match '^((?:collections/[^/]+/)?(?:dataStores|engines)/[^/]+)(?:/.*)?$') {
        [void]$discoveryNames.Add("projects/$proj/locations/$loc/" + $Matches[1])
    } else {
        [void]$discoveryUnsupported.Add(($rest -split '/')[0])
    }
}
function Get-DiscoveryEndpoint([string]$Location) {
    if ($Location -eq 'global') { return 'https://discoveryengine.googleapis.com/v1/' }
    return 'https://' + $Location + '-discoveryengine.googleapis.com/v1/'
}
function Get-EscapedPath([string]$ResourceName) {
    return (($ResourceName -split '/') | ForEach-Object { E $_ }) -join '/'
}
$idx=0
foreach ($pair in $discoveryLocations) {
    $idx++
    $proj, $loc = $pair -split '\|', 2
    $parent = Get-EscapedPath "projects/$proj/locations/$loc/collections/default_collection"
    $base = Get-DiscoveryEndpoint $loc
    RestList 'ai' "discovery_datastores_$idx" ($base + $parent + '/dataStores?pageSize=100') 'discoveryengine.googleapis.com' 'dataStores'
    RestList 'ai' "discovery_engines_$idx" ($base + $parent + '/engines?pageSize=100') 'discoveryengine.googleapis.com' 'engines'
}
$idx=0
foreach ($resourceName in $discoveryNames) {
    if ($MaxDetailItems -gt 0 -and $idx -ge $MaxDetailItems) { break }
    $idx++
    $loc = ($resourceName -split '/')[3]
    Invoke-RestEvidence 'ai' "discovery_resource_$idx" ((Get-DiscoveryEndpoint $loc) + (Get-EscapedPath $resourceName)) 'discoveryengine.googleapis.com'
}
$idx=0
foreach ($type in $discoveryUnsupported) {
    $idx++
    Add-ManifestEntry 'ai' "discovery_unsupported_$idx" 'UNSUPPORTED_ENDPOINT' 'discoveryengine.googleapis.com' ("NOT_REQUESTED discoveryengine resource type '" + ($type -replace '[^A-Za-z0-9_-]','_') + "' has no supported v1 GET")
}

# IAM hierarchy and resource policy enrichment. Read-only. Each operation is separately logged.
# Search at the parent scope exposes additional visible IAM policies, including inherited grants.
$parentNodes = New-Object 'System.Collections.Generic.List[object]'
$cursor = $project.parent
$seenParents = @{}
for ($depth = 0; $depth -lt 20 -and $null -ne $cursor; $depth++) {
    $kind = [string]$cursor.type
    $identifier = [string]$cursor.id
    if (-not $identifier -or $seenParents.ContainsKey("$kind/$identifier")) { break }
    $seenParents["$kind/$identifier"] = $true
    $parentNodes.Add([pscustomobject]@{type=$kind;id=$identifier})
    if ($kind -eq 'organization') { break }
    if ($kind -ne 'folder') { break }
    $nodeName = 'folders/' + $identifier
    $nodeDataset = 'folder_' + $identifier
    Run 'identity' ($nodeDataset + '_iam') @('resource-manager','folders','get-iam-policy',$identifier)
    Run 'governance' ($nodeDataset + '_policies') @('org-policies','list',"--folder=$identifier")
    if ($IncludeOrganizationSearch) {
        Run 'inventory' ($nodeDataset + '_iam_search') @('asset','search-all-iam-policies',"--scope=$nodeName")
    }
    Run 'inventory' ($nodeDataset + '_describe') @('resource-manager','folders','describe',$identifier)
    $folderDetailsPath = Join-Path $root ('inventory/' + $nodeDataset + '_describe.json')
    if (-not (Test-Path -LiteralPath $folderDetailsPath)) { break }
    try {
        $folderDetails = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($folderDetailsPath))
        $parentName = [string]$folderDetails.parent
        if ($parentName -match '^folders/(\d+)$') { $cursor = [pscustomobject]@{type='folder';id=$Matches[1]} }
        elseif ($parentName -match '^organizations/(\d+)$') { $cursor = [pscustomobject]@{type='organization';id=$Matches[1]} }
        else { break }
    } catch { break }
}
foreach ($node in $parentNodes) {
    if ($node.type -eq 'organization') {
        $orgScope = 'organizations/' + $node.id
        Run 'identity' ('organization_' + $node.id + '_iam') @('organizations','get-iam-policy',([string]$node.id))
        if ($IncludeOrganizationSearch) {
            Run 'inventory' ('organization_' + $node.id + '_iam_search') @('asset','search-all-iam-policies',"--scope=$orgScope")
        }
        Run 'governance' ('organization_' + $node.id + '_policies') @('org-policies','list',('--organization=' + $node.id))
    }
}
# Retrieve project IAM with policy version 3 so IAM conditions are represented when available.
# Cloud Resource Manager getIamPolicy supports requestedPolicyVersion=3.
# Expand project custom roles and federated workload identity provider policies.
# 2.2.8: 'gcloud iam roles describe' takes the bare role ID and its scope flag; the listed name is
# projects/<id>/roles/<role> or organizations/<number>/roles/<role>. Other shapes are skipped.
function Get-RoleDescribeArguments([string]$Name) {
    if ($Name -match '^projects/([a-z][a-z0-9.:-]{4,62})/roles/([A-Za-z0-9_.]{1,64})$') {
        return ,@('iam', 'roles', 'describe', $Matches[2], ('--project=' + $Matches[1]))
    }
    if ($Name -match '^organizations/([0-9]{1,20})/roles/([A-Za-z0-9_.]{1,64})$') {
        return ,@('iam', 'roles', 'describe', $Matches[2], ('--organization=' + $Matches[1]))
    }
    return $null
}
$customRoles = @(Read-EvidenceArray 'identity/custom_roles.json')
$roleIndex=0
foreach ($role in $customRoles) {
    if (-not $role.name) { continue }
    $describeArguments = Get-RoleDescribeArguments ([string]$role.name)
    if ($null -eq $describeArguments) {
        Write-Host ('Custom role name not recognised; detail skipped: ' + [string]$role.name) -ForegroundColor Yellow
        continue
    }
    if ($MaxDetailItems -gt 0 -and $roleIndex -ge $MaxDetailItems) { $DetailLimits['custom_roles'] = $true; break }
    $roleIndex++
    Run 'identity' ('custom_role_detail_'+$roleIndex) $describeArguments
}
$pools = @(Read-EvidenceArray 'identity/workload_identity_pools.json')
$poolIndex=0
foreach ($pool in $pools) {
    if (-not $pool.name) { continue }
    $poolIndex++
    $poolName = [string]$pool.name
    Run 'identity' ('workload_pool_providers_'+$poolIndex) @('iam','workload-identity-pools','providers','list',('--workload-identity-pool='+($poolName -split '/')[-1]),'--location=global',"--project=$ProjectId")
}
# Effective organization policies (2.2.7). gcloud lists constraints as bare names
# (gcp.resourceLocations), 'constraints/x' or '.../policies/x'; all are reduced to the bare
# name, unioned with a fixed security baseline, de-duplicated and described with --effective.
function ConvertTo-ConstraintName([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $text = $Value.Trim()
    if ($text -match '(?:^|/)(?:constraints|policies)/([A-Za-z][A-Za-z0-9_.]{0,199})$') { return $Matches[1] }
    if ($text -match '^[A-Za-z][A-Za-z0-9_]*\.[A-Za-z0-9_.]{1,199}$') { return $text }
    return ''
}
$EffectivePolicyBaseline = @('iam.disableServiceAccountKeyCreation','iam.disableServiceAccountKeyUpload','iam.allowedPolicyMemberDomains','compute.requireOsLogin','compute.disableSerialPortAccess','compute.vmExternalIpAccess','compute.skipDefaultNetworkCreation','storage.publicAccessPrevention','storage.uniformBucketLevelAccess','sql.restrictPublicIp','gcp.resourceLocations')
$policyNames = New-Object 'System.Collections.Generic.List[string]'
foreach ($baseline in $EffectivePolicyBaseline) { [void]$policyNames.Add($baseline) }
foreach ($relative in @('governance/org_policies.json','governance/parent_org_policies.json')) {
    foreach ($policy in @(Read-EvidenceArray $relative)) {
        if ($null -eq $policy) { continue }
        $constraint = ConvertTo-ConstraintName ([string]$policy.constraint)
        if (-not $constraint) { $constraint = ConvertTo-ConstraintName ([string]$policy.name) }
        if ($constraint -and -not $policyNames.Contains($constraint)) { [void]$policyNames.Add($constraint) }
    }
}
$constraintIndex=0
foreach ($constraint in $policyNames) {
    $constraintIndex++
    Run 'governance' ('effective_policy_'+$constraintIndex) @('org-policies','describe',$constraint,'--effective',"--project=$ProjectId")
}
Write-AtomicText (Join-Path $root 'iam_parent_hierarchy_attempted.json') (ConvertTo-Json -InputObject @($parentNodes.ToArray()) -Depth 6)


# ---- Expanded read-only security evidence collection, workbook-aligned ----
# These are metadata/configuration endpoints only; no secret values or workload data.
$P=E $ProjectId; $OrgNode=@($parentNodes | Where-Object { $_.type -eq 'organization' } | Select-Object -First 1); $OrgParent=$(if ($OrgNode.Count -gt 0) { '&parent='+(E ('organizations/'+[string]$OrgNode[0].id)) } else { '' })  # 2.2.4: workforce pools and access policies list under an organization parent
# IAM v3: preserve conditional bindings, IAM deny and principal access boundary policy inventory.
# IAM v2 deny policy parent is a cloud resource attachment point, not policies/projects/{id}.
# Project number is required for the cloudresourcemanager.googleapis.com project attachment.
$ProjectNumber = [string]$project.projectNumber
if (-not [string]::IsNullOrWhiteSpace($ProjectNumber)) {
 RestList 'identity' 'deny_policies_project' ('https://iam.googleapis.com/v2/policies/cloudresourcemanager.googleapis.com%2Fprojects%2F'+$ProjectNumber+'/denypolicies?pageSize=1000') 'iam.googleapis.com' 'policies'
}
RestList 'identity' 'principal_access_boundaries_project' ('https://iam.googleapis.com/v3/projects/'+$P+'/locations/global/policyBindings?pageSize=1000') 'iam.googleapis.com' 'policyBindings'
RestList 'identity' 'workforce_pools' ('https://iam.googleapis.com/v1/locations/global/workforcePools?pageSize=1000'+$OrgParent) 'iam.googleapis.com' 'workforcePools'
RestList 'identity' 'iam_recommendations' ('https://recommender.googleapis.com/v1/projects/'+$P+'/locations/global/recommenders/google.iam.policy.Recommender/recommendations?pageSize=1000') 'recommender.googleapis.com' 'recommendations'
# Security and access context configuration.
RestList 'security' 'access_context_policies' ('https://accesscontextmanager.googleapis.com/v1/accessPolicies?pageSize=1000'+$OrgParent) 'accesscontextmanager.googleapis.com' 'accessPolicies'
RestList 'security' 'scc_sources' ('https://securitycenter.googleapis.com/v1/projects/'+$P+'/sources?pageSize=1000') 'securitycenter.googleapis.com' 'sources'
RestList 'security' 'scc_findings_rest' ('https://securitycenter.googleapis.com/v1/projects/'+$P+'/sources/-/findings?pageSize=1000') 'securitycenter.googleapis.com' 'listFindingsResults'
# Regional discovery from actual enabled locations, not hardcoded region samples.
RestList 'inventory' 'compute_regions_rest' ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/regions?maxResults=500') 'compute.googleapis.com' 'items'
RestList 'inventory' 'compute_zones_rest' ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/zones?maxResults=500') 'compute.googleapis.com' 'items'
RestList 'security' 'kms_locations_rest' ('https://cloudkms.googleapis.com/v1/projects/'+$P+'/locations?pageSize=1000') 'cloudkms.googleapis.com' 'locations'
RestList 'security' 'secrets_rest' ('https://secretmanager.googleapis.com/v1/projects/'+$P+'/secrets?pageSize=1000') 'secretmanager.googleapis.com' 'secrets'
RestList 'data' 'sql_instances_rest' ('https://sqladmin.googleapis.com/sql/v1beta4/projects/'+$P+'/instances?maxResults=500') 'sqladmin.googleapis.com' 'items'
RestList 'compute' 'gke_clusters_rest' ('https://container.googleapis.com/v1/projects/'+$P+'/locations/-/clusters') 'container.googleapis.com' 'clusters'
RestList 'serverless' 'run_services_rest' ('https://run.googleapis.com/v2/projects/'+$P+'/locations/-/services?pageSize=1000') 'run.googleapis.com' 'services'
# 2.2.5: Cloud Run jobs come from 'cloud_run_jobs' (gcloud covers every region); the v2 REST list rejects the '-' location (HTTP 400).
RestList 'serverless' 'functions_rest' ('https://cloudfunctions.googleapis.com/v2/projects/'+$P+'/locations/-/functions?pageSize=1000') 'cloudfunctions.googleapis.com' 'functions'
RestList 'monitoring' 'notification_channels' ('https://monitoring.googleapis.com/v3/projects/'+$P+'/notificationChannels?pageSize=1000') 'monitoring.googleapis.com' 'notificationChannels'
RestList 'monitoring' 'uptime_check_configs' ('https://monitoring.googleapis.com/v3/projects/'+$P+'/uptimeCheckConfigs?pageSize=1000') 'monitoring.googleapis.com' 'uptimeCheckConfigs'
RestList 'network' 'dns_policies' ('https://dns.googleapis.com/dns/v1/projects/'+$P+'/policies?maxResults=500') 'dns.googleapis.com' 'policies'
RestList 'network' 'vpc_peerings' ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/global/networks?maxResults=500') 'compute.googleapis.com' 'items'
RestList 'network' 'global_security_policies_rest' ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/global/securityPolicies?maxResults=500') 'compute.googleapis.com' 'items'
RestList 'network' 'interconnect_attachments' ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/aggregated/interconnectAttachments?maxResults=500') 'compute.googleapis.com' 'items'
RestList 'network' 'psc_forwarding_rules' ('https://compute.googleapis.com/compute/v1/projects/'+$P+'/aggregated/forwardingRules?maxResults=500') 'compute.googleapis.com' 'items'
RestList 'data' 'bigquery_connections' ('https://bigqueryconnection.googleapis.com/v1/projects/'+$P+'/locations/-/connections?pageSize=1000') 'bigqueryconnection.googleapis.com' 'connections'
# 2.2.5: repositories come from 'artifact_repositories' (gcloud --location=all); the REST list rejects the '-' location (HTTP 400).
RestList 'devops' 'cloudbuild_triggers_rest' ('https://cloudbuild.googleapis.com/v1/projects/'+$P+'/triggers?pageSize=1000') 'cloudbuild.googleapis.com' 'triggers'
# Expand discovered resources. Each object gets a unique local dataset name.
$kmsLocs=@(Read-EvidenceArray 'security/kms_locations_rest.json')
$ix=0
foreach($loc in $kmsLocs) {
 if(-not $loc.name) {continue}; $ix++
 $locName=[string]$loc.name
 $locUrl='https://cloudkms.googleapis.com/v1/'+$locName
 RestList 'security' ('kms_keyrings_'+$ix) ($locUrl+'/keyRings?pageSize=1000') 'cloudkms.googleapis.com' 'keyRings'
 $rings=@(Read-EvidenceArray ('security/kms_keyrings_'+$ix+'.json'))
 $j=0
 foreach($ring in $rings) {
  if(-not $ring.name){continue}
  if($MaxDetailItems -gt 0 -and $j -ge $MaxDetailItems){$DetailLimits['kms']=$true;break}
  $j++
  RestList 'security' ('kms_keys_'+$ix+'_'+$j) ('https://cloudkms.googleapis.com/v1/'+[string]$ring.name+'/cryptoKeys?pageSize=1000') 'cloudkms.googleapis.com' 'cryptoKeys'
  $keys=@(Read-EvidenceArray ('security/kms_keys_'+$ix+'_'+$j+'.json'))
  $k=0
  foreach($key in $keys) {
   if(-not $key.name){continue}
   if($MaxDetailItems -gt 0 -and $k -ge $MaxDetailItems){$DetailLimits['kms']=$true;break}
   $k++
   $keyUrl='https://cloudkms.googleapis.com/v1/'+[string]$key.name
   RestList 'security' ('kms_versions_'+$ix+'_'+$j+'_'+$k) ($keyUrl+'/cryptoKeyVersions?pageSize=1000') 'cloudkms.googleapis.com' 'cryptoKeyVersions'
  }
 }
}
$ix=0
foreach($secret in @(Read-EvidenceArray 'security/secrets_rest.json')) {
 if(-not $secret.name){continue};$ix++
 RestList 'security' ('secret_versions_'+$ix) ('https://secretmanager.googleapis.com/v1/'+[string]$secret.name+'/versions?pageSize=1000') 'secretmanager.googleapis.com' 'versions'
}
# Per-resource GKE cluster configuration is included in cluster list responses; node pools are expanded.
$ix=0
foreach($cluster in @(Read-EvidenceArray 'compute/gke_clusters_rest.json')) {
 if(-not $cluster.name){continue};$ix++
 $clusterName=[string]$cluster.name
 if($clusterName -match '^projects/[^/]+/locations/[^/]+/clusters/[^/]+$') { $path=$clusterName }
 elseif($cluster.location) { $path='projects/'+$P+'/locations/'+(E ([string]$cluster.location))+'/clusters/'+(E $clusterName) }
 else { continue }
 RestList 'compute' ('gke_node_pools_'+$ix) ('https://container.googleapis.com/v1/'+$path+'/nodePools') 'container.googleapis.com' 'nodePools'
}
# Per-resource IAM collection through supported gcloud commands.
# 2.2.6: the REST lists name each service/function. When a REST list failed, the gcloud lists
# collected earlier ('cloud_run', 'functions') supply the targets instead, and the substitution is
# recorded in dependency_fallbacks with both statuses, so IAM evidence never disappears silently.
$ListUsable = @('SUCCESS','EMPTY','PARTIAL','TRUNCATED')
function Get-ServerlessTargets([string]$Family, [string]$RestDataset, [string]$GcloudDataset) {
    $targets = New-Object 'System.Collections.Generic.List[object]'
    $restStatus = Get-ManifestStatus 'serverless' $RestDataset
    if ($ListUsable -contains $restStatus) {
        foreach ($item in @(Read-EvidenceArray ('serverless/' + $RestDataset + '.json'))) {
            if ($null -eq $item -or -not $item.name) { continue }
            $parts = ([string]$item.name) -split '/'
            if ($parts.Length -ge 6) { [void]$targets.Add([pscustomobject]@{name=$parts[-1]; region=$parts[3]}) }
        }
        return ,$targets
    }
    # 2.2.7: a list skipped as API_DISABLED leaves nothing to fall back to; no fallback is recorded.
    if ($restStatus -eq 'API_DISABLED') { return ,$targets }
    $gcloudStatus = Get-ManifestStatus 'serverless' $GcloudDataset
    foreach ($item in @(Read-EvidenceArray ('serverless/' + $GcloudDataset + '.json'))) {
        if ($null -eq $item) { continue }
        $name = $null; $region = $null
        if ($item.name -and ([string]$item.name) -match '^projects/[^/]+/locations/([^/]+)/(?:services|functions)/([^/]+)$') {
            $region = $Matches[1]; $name = $Matches[2]
        } elseif ($null -ne $item.metadata -and $item.metadata.name) {
            # gcloud run services list returns Knative-style objects.
            $name = [string]$item.metadata.name
            if ($null -ne $item.metadata.labels) { $region = [string]$item.metadata.labels.'cloud.googleapis.com/location' }
        }
        if ($name -and $region) { [void]$targets.Add([pscustomobject]@{name=$name; region=$region}) }
    }
    [void]$script:Fallbacks.Add([pscustomobject]@{
        dataset_family=$Family; failed_dependency=('serverless/' + $RestDataset); failed_status=$restStatus;
        fallback_source=('serverless/' + $GcloudDataset); fallback_status=$gcloudStatus; targets=$targets.Count
    })
    Write-Host "[$Family] REST list $RestDataset is $restStatus; using gcloud list $GcloudDataset ($gcloudStatus, $($targets.Count) targets)." -ForegroundColor Yellow
    return ,$targets
}
$ix=0
foreach($target in (Get-ServerlessTargets 'run_iam' 'run_services_rest' 'cloud_run')) {
 $ix++
 Run 'serverless' ('run_iam_'+$ix) @('run','services','get-iam-policy',$target.name,('--region='+$target.region),('--project='+$ProjectId)) 'run.googleapis.com'
}
$ix=0
foreach($target in (Get-ServerlessTargets 'function_iam' 'functions_rest' 'functions')) {
 $ix++
 Run 'serverless' ('function_iam_'+$ix) @('functions','get-iam-policy',$target.name,('--region='+$target.region),('--project='+$ProjectId)) 'cloudfunctions.googleapis.com'
}
# ---- End workbook-aligned expansion ----

$CollectionStatus = 'COMPLETE'
} finally {
# The manifest is always written, including after Ctrl+C or an unexpected failure, so
# partial evidence is never mistaken for a complete collection.
$typeCounts=@{}
foreach ($asset in @($assets)) {
    if ($null -eq $asset) { continue }
    $type=[string]$asset.assetType
    if (-not $type) { $type='UNKNOWN' }
    if (-not $typeCounts.ContainsKey($type)) { $typeCounts[$type]=0 }
    $typeCounts[$type]++
}
$typeRows=@($typeCounts.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{asset_type=$_;count=$typeCounts[$_]} })
Write-AtomicText (Join-Path $root 'discovered_asset_types.json') (ConvertTo-Json -InputObject $typeRows -Depth 6)

$summary = [pscustomobject]@{
    schema_version=$SchemaVersion; collector='GCP_Security_Evidence_Collector.ps1'; collector_version=$CollectorVersion;
    project_id=$ProjectId; project_name=$pname;
    collected_utc=(Get-Date).ToUniversalTime().ToString('o'); scope='project';
    collection_status=$CollectionStatus;
    quota_project=$(if ($QuotaProject) { $QuotaProject } else { $null });
    command_timeout_seconds=$CommandTimeoutSeconds; http_max_retries=$HttpMaxRetries; page_hard_cap=$PageHardCap;
    limitations=@(
        'Evidence collection is scoped to the selected project and reachable ancestor APIs',
        'Logging exclusions attempted through REST; access may restrict results',
        'API_DISABLED indicates API not enabled when enabled-services inventory is available, not proof of zero assets',
        'Organization/folder inherited IAM and effective policies not fully collected',
        'SCC findings attempted only if SCC API enabled; permissions and SCC scope may limit coverage',
        'Regional and resource-specific security configuration not exhaustive; selected regions are samples',
        'Discovery Engine metadata and BigQuery datasets are inspected when visible, but data content is never collected',
        'No access to organization-wide inherited IAM or effective policies is inferred from project IAM',
        'TRUNCATED means maximum pagination/detail budget reached; do not treat as complete',
        'PARTIAL means the API reported unreachable locations; UNEXPECTED_SCHEMA means the response shape was not recognized',
        'TIMEOUT, QUOTA_PROJECT_DENIED and UNSUPPORTED_ENDPOINT are collection gaps, not security results',
        'CAI resource/IAM asset list and parent IAM collection are best effort and subject to current identity access',
        'API keys and bucket metadata may be sensitive; store output securely',
        'Evidence may contain VM startup scripts and instance metadata, Cloud Run and Cloud Functions environment variables, and Cloud Build substitutions; these can hold secrets. Handle the package as sensitive',
        'detail_limits_reached lists detail loops stopped by -MaxDetailItems; their remaining items were not described',
        'dependency_fallbacks lists IAM collections whose REST target list failed and that used the gcloud list instead',
        'Missing or failed evidence must not be treated as PASS'
    );
    max_detail_items=$MaxDetailItems; max_api_pages=$MaxApiPages; enabled_api_count=$EnabledApis.Count;
    discovered_asset_types=$typeRows;
    discovery_engine_detail_limit_reached=($MaxDetailItems -gt 0 -and @($discoveryNames).Count -gt $MaxDetailItems);
    bigquery_dataset_detail_limit_reached=($MaxDetailItems -gt 0 -and @($bqDatasets).Count -gt $MaxDetailItems);
    detail_limits_reached=[pscustomobject]$DetailLimits;
    dependency_fallbacks=@($Fallbacks.ToArray());
    datasets=@($manifest.ToArray())
}
$manifestFile = Join-Path $root 'collection_manifest.json'
Write-AtomicText $manifestFile ($summary | ConvertTo-Json -Depth 15)
# Source checksums for every evidence file, verified by the analyzer before import.
$checksumLines = Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object { $_.Name -ne 'checksums.sha256' -and $_.Name -notlike '*.partial' -and $_.Name -notlike '*.tmp' } |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($root.Length).TrimStart('\','/') -replace '\\','/'
        (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $relative
    }
Write-AtomicText (Join-Path $root 'checksums.sha256') ((@($checksumLines) -join "`n") + "`n")
if ($null -ne $RestSession) { $RestSession.Dispose() }
}
# 2.2.6: build the ZIP entry by entry with explicit forward-slash names. Compress-Archive (and
# ZipFile.CreateFromDirectory on older .NET Framework) can write backslash entry names on
# Windows PowerShell 5.1, which other platforms read as file names, not folders.
function New-EvidenceZip([string]$Source, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $partial = "$Destination.partial"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    $base = (Resolve-Path -LiteralPath $Source).ProviderPath.TrimEnd('\','/')
    $archive = [System.IO.Compression.ZipFile]::Open($partial, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $base -Recurse -File | Sort-Object FullName)) {
            if ($file.Name -like '*.partial' -or $file.Name -like '*.tmp') { continue }
            $entryName = $file.FullName.Substring($base.Length).TrimStart('\','/') -replace '\\','/'
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    } finally { $archive.Dispose() }
    $check = [System.IO.Compression.ZipFile]::OpenRead($partial)
    try { $badNames = @($check.Entries | Where-Object { $_.FullName.Contains('\') }).Count; $entries = $check.Entries.Count }
    finally { $check.Dispose() }
    if ($badNames -gt 0) {
        Remove-Item -LiteralPath $partial -Force
        throw "ZIP verification failed: $badNames entry names contain backslashes."
    }
    Move-Item -LiteralPath $partial -Destination $Destination -Force
    return $entries
}
$zip = $null
$zipSha256 = $null
if ($CollectionStatus -eq 'COMPLETE') {
    $zip = "$root.zip"
    try {
        $zipEntries = New-EvidenceZip $root $zip
        $zipSha256 = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        # The manifest is inside the ZIP, so the ZIP digest is written beside it.
        Write-AtomicText "$zip.sha256" ($zipSha256 + '  ' + (Split-Path -Leaf $zip) + "`n")
    }
    catch { Write-Warning "ZIP packaging failed: $($_.Exception.Message)"; $zip = $null; $zipSha256 = $null }
} else {
    Write-Warning 'Collection did not complete; evidence directory retained without ZIP. Collection status INTERRUPTED.'
}
Write-Host "`nEvidence directory: $root" -ForegroundColor Green
if ($zip) {
    Write-Host "ZIP: $zip ($zipEntries entries, forward-slash names verified)"
    Write-Host "ZIP SHA-256: $zipSha256 (also in $zip.sha256)"
}
$limited = @($DetailLimits.Keys | Where-Object { $DetailLimits[$_] })
if ($limited.Count -gt 0) { Write-Warning ("-MaxDetailItems stopped these detail loops: " + ($limited -join ', ')) }
foreach ($fallback in $Fallbacks) { Write-Warning ("$($fallback.dataset_family): $($fallback.failed_dependency) was $($fallback.failed_status); used $($fallback.fallback_source) ($($fallback.fallback_status), $($fallback.targets) targets).") }
$manifest | Group-Object status | ForEach-Object { Write-Host "$($_.Name): $($_.Count)" }
# A session that expires during collection shows up as AUTH_ERROR or gcloud auth-token errors.
$authFailures = @($manifest | Where-Object {
    $_.status -eq 'AUTH_ERROR' -or ($_.error_file -and
        (Test-Path -LiteralPath (Join-Path $root $_.error_file) -PathType Leaf) -and
        ([string](Get-Content -LiteralPath (Join-Path $root $_.error_file) -Raw -ErrorAction SilentlyContinue) -match 'auth tokens|Reauthentication|gcloud auth login'))
}).Count
if ($authFailures -gt 0) {
    Write-Warning "$authFailures datasets failed because the gcloud sign-in expired or needs reauthentication. Run gcloud auth login and collect again; do not import this package."
}
Write-Host 'Review failed datasets and limitations before using evidence for findings.' -ForegroundColor Yellow
