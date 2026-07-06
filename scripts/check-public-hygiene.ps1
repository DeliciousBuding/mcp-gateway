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

$files = Get-ChildItem -LiteralPath $Root -Recurse -File -Force |
  Where-Object {
    $_.FullName -notmatch "\\\.git\\" -and
    $_.FullName -notmatch "\\bin\\" -and
    $_.FullName -notmatch "\\tmp\\" -and
    $_.FullName -notmatch "\\dist\\" -and
    $_.FullName -ne $PSCommandPath
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
