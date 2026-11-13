$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot
$env:PYTHONPATH = Join-Path $PSScriptRoot "src"
$version = "0.2.0"

# Remove old onedir output so a locked/stale exe can never be paired with a
# freshly collected _internal directory.
if (Test-Path "dist") { Remove-Item "dist" -Recurse -Force }
New-Item -ItemType Directory "dist" | Out-Null

Write-Host "== unit tests =="
python -m unittest discover -s tests -v

Write-Host "== build GUI (portable onedir) =="
python -m PyInstaller `
  --noconfirm --clean --onedir --windowed `
  --name "TGCT526G-Audit" `
  --icon "assets/icon.ico" `
  --add-data "assets;assets" `
  --paths "src" `
  "src/tgct526g/__main__.py"

Write-Host "== build CLI (portable onedir) =="
python -m PyInstaller `
  --noconfirm --clean --onedir --console `
  --name "tgct526g-cli" `
  --icon "assets/icon.ico" `
  --add-data "assets;assets" `
  --paths "src" `
  "src/tgct526g/__main__.py"

Copy-Item README.md, LICENSE -Destination "dist/TGCT526G-Audit" -Force
Copy-Item README.md, LICENSE -Destination "dist/tgct526g-cli" -Force

$guiZip = "dist/TGCT526G-Audit-$version-win64.zip"
$cliZip = "dist/tgct526g-cli-$version-win64.zip"
if (Test-Path $guiZip) { Remove-Item $guiZip -Force }
if (Test-Path $cliZip) { Remove-Item $cliZip -Force }
Compress-Archive -Path "dist/TGCT526G-Audit/*" -DestinationPath $guiZip -CompressionLevel Optimal
Compress-Archive -Path "dist/tgct526g-cli/*" -DestinationPath $cliZip -CompressionLevel Optimal

$hashes = @()
foreach ($file in @($guiZip, $cliZip)) {
  $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
  $hashes += "$hash  $([System.IO.Path]::GetFileName($file))"
}
$hashes | Set-Content -Path "dist/SHA256SUMS.txt" -Encoding ASCII

Write-Host "== done =="
Get-ChildItem dist | Select-Object Name, Length
Get-Content dist/SHA256SUMS.txt
