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

$trackedFiles = & git -C $Root ls-files |
  Where-Object { $_ -and $_ -ne "scripts/check-public-hygiene.ps1" }

$files = foreach ($path in $trackedFiles) {
  Get-Item -LiteralPath (Join-Path $Root $path)
}

$violations = @()
foreach ($file in $files) {
  $text = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction SilentlyContinue
  foreach ($pattern in $patterns) {
    if ($text -match $pattern) {
      $relative = Resolve-Path -LiteralPath $file.FullName -Relative
      $violations += "${relative}: matched /$pattern/"
    }
  }
}

if ($violations.Count -gt 0) {
  Write-Error ("Public hygiene check failed:`n" + ($violations -join "`n"))
}

Write-Host "public hygiene ok"
