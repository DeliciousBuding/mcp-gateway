param(
  [string]$Root = (Resolve-Path "$PSScriptRoot\..").Path
)

$ErrorActionPreference = "Stop"

$patterns = @(
  "vectorcontrol\.tech",
  "api\.vectorcontrol",
  "id\.vectorcontrol",
  "mcp\.vectorcontrol",
  "agents\.vectorcontrol",
  "C:\\Users\\Ding",
  "D:\\Code",
  "\bhk[0-9]\b",
  "\bus[0-9]\b"
)

$candidateFiles = & git -C $Root ls-files --cached --others --exclude-standard |
  ForEach-Object { $_.Trim() } |
  Where-Object { $_ -and $_ -ne "scripts/check-public-hygiene.ps1" }

$violations = @()
foreach ($path in $candidateFiles) {
  $fullPath = Join-Path $Root $path
  if (Test-Path -LiteralPath $fullPath) {
    $text = Get-Content -Raw -LiteralPath $fullPath -ErrorAction SilentlyContinue
  } else {
    $text = (& git -C $Root show "HEAD:$path") -join "`n"
  }
  foreach ($pattern in $patterns) {
    if ($text -match $pattern) {
      $violations += "${path}: matched /$pattern/"
    }
  }
}

if ($violations.Count -gt 0) {
  Write-Error ("Public hygiene check failed:`n" + ($violations -join "`n"))
}

Write-Host "public hygiene ok"
