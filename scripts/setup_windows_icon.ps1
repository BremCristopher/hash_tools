# Hash Tools - Windows 图标设置脚本
# 将 PNG 转换为 ICO 格式
#
# 前置条件:
#   需要安装 ImageMagick: winget install ImageMagick.ImageMagick
#   或从官网下载: https://imagemagick.org/script/download.php#windows
#
# 使用方法:
#   1. 将 icon.png (256x256 或更大) 放入 assets 目录
#   2. 运行此脚本: .\scripts\setup_windows_icon.ps1
#   3. 重新编译项目: cargo build --release

param(
    [string]$InputPng = "assets\icon.png",
    [string]$OutputIco = "assets\icon.ico"
)

$ErrorActionPreference = "Stop"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Hash Tools Windows 图标设置工具" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 检查输入文件
if (-not (Test-Path $InputPng)) {
    Write-Host "[-] 错误: 找不到 $InputPng" -ForegroundColor Red
    Write-Host "    请确保 icon.png 文件存在于 assets 目录中" -ForegroundColor Gray
    exit 1
}

Write-Host "[*] 输入文件: $InputPng" -ForegroundColor White

# 检查 ImageMagick 是否安装
$magick = Get-Command "magick" -ErrorAction SilentlyContinue

if (-not $magick) {
    Write-Host "`n[-] 未找到 ImageMagick!" -ForegroundColor Yellow
    Write-Host "`n要安装 ImageMagick,请选择以下方式之一:" -ForegroundColor White
    Write-Host "  1. winget install ImageMagick.ImageMagick" -ForegroundColor Gray
    Write-Host "  2. https://imagemagick.org/script/download.php#windows" -ForegroundColor Gray
    Write-Host "`n或者,您可以使用在线转换工具:" -ForegroundColor White
    Write-Host "  - https://icoconvert.com/" -ForegroundColor Gray
    Write-Host "  - https://convertico.com/" -ForegroundColor Gray
    Write-Host "`n转换时请选择以下尺寸: 16x16, 32x32, 48x48, 256x256" -ForegroundColor White
    exit 1
}

Write-Host "[+] ImageMagick 已找到: $($magick.Path)" -ForegroundColor Green

# 创建多尺寸 ICO 文件
# ICO 格式需要包含多个尺寸以支持:
#   - 16x16: 小图标 (标题栏, 任务栏)
#   - 32x32: 标准图标
#   - 48x48: 大图标
#   - 256x256: 高 DPI 显示

Write-Host "`n[*] 正在生成多尺寸 ICO 文件..." -ForegroundColor Yellow

# 使用 ImageMagick 转换
# -define icon:auto-resize 自动创建所需尺寸
& magick convert $InputPng `
    -define icon:auto-resize="256,128,96,64,48,32,24,16" `
    -compress zip `
    $OutputIco

if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] ICO 转换失败!" -ForegroundColor Red
    exit 1
}

# 验证输出文件
if (Test-Path $OutputIco) {
    $icoSize = (Get-Item $OutputIco).Length
    Write-Host "[+] ICO 文件已生成: $OutputIco ($icoSize bytes)" -ForegroundColor Green
} else {
    Write-Host "[-] 错误: ICO 文件未生成" -ForegroundColor Red
    exit 1
}

# 完成提示
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  图标设置完成!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n下一步操作:" -ForegroundColor Yellow
Write-Host "  1. 重新编译项目:" -ForegroundColor White
Write-Host "     cargo build --release" -ForegroundColor Gray
Write-Host "`n  2. 检查生成的 EXE:" -ForegroundColor White
Write-Host "     - 在资源管理器中查看 target\release\hash_tools.exe" -ForegroundColor Gray
Write-Host "     - 文件图标应显示为新图标" -ForegroundColor Gray
Write-Host "     - 运行程序,检查窗口标题栏和任务栏图标" -ForegroundColor Gray

Write-Host "`n" -ForegroundColor White
