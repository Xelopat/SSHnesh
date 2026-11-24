$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$artifacts = Join-Path $repo 'dist/tauri-preview'
$release = '0.1.2-native'
$folder = '0.1.2'
$stage = Join-Path $repo 'dist/sshnesh-site-public'
$downloads = Join-Path $stage "downloads/$folder"
$names = @(
  "SSHnesh-$release-win-x64.zip"
  "SSHnesh-$release-linux-amd64.deb"
  "SSHnesh-$release-android-arm64.apk"
)
$index = Join-Path $PSScriptRoot 'public/index.php'
$markup = Get-Content -LiteralPath $index -Raw -Encoding UTF8
foreach ($name in $names) {
  if (!(Test-Path -LiteralPath (Join-Path $artifacts $name) -PathType Leaf) -or
      !$markup.Contains("/downloads/$folder/$name")) {
    throw "The page or build is missing: $name"
  }
}
New-Item -ItemType Directory -Path $downloads -Force | Out-Null
foreach ($name in $names) {
  Copy-Item -LiteralPath (Join-Path $artifacts $name) -Destination $downloads -Force
}
$names | ForEach-Object {
  $hash = (Get-FileHash -LiteralPath (Join-Path $downloads $_) -Algorithm SHA256).Hash.ToLowerInvariant()
  "$hash  $_"
} | Set-Content -LiteralPath (Join-Path $downloads 'SHA256SUMS') -Encoding Ascii
Copy-Item -LiteralPath $index -Destination $stage -Force
$preview = $markup.Substring($markup.IndexOf('<!doctype html>'))
$preview = $preview -replace '<style nonce="[^\r\n]+">', '<style>' -replace 'href="/downloads/', 'href="downloads/'
[IO.File]::WriteAllText((Join-Path $stage 'index.html'), $preview, [Text.UTF8Encoding]::new($false))
$archive = Join-Path $repo "dist/SSHnesh-site-$release.zip"
Push-Location -LiteralPath $stage
try {
  # Keep old revisions available locally, but only ship the release linked from this page.
  tar.exe -a -cf $archive index.php "downloads/$folder"
  if ($LASTEXITCODE -ne 0) { throw 'Failed to package website downloads' }
} finally { Pop-Location }
Get-Item -LiteralPath $archive
