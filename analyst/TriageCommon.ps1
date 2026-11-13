# Analyst-side entry point. The analysis and report code is shared with the collector (shared/*.ps1).
foreach ($sharedFile in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..\shared') -Filter '*.ps1' | Sort-Object Name)) {
    . $sharedFile.FullName
}
