# Hash Tools - Windows 自签名证书生成脚本
# 用于 SignTool 代码签名
#
# 使用方法:
#   1. 以管理员身份运行 PowerShell
#   2. 执行: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
#   3. 执行: .\scripts\create_code_signing_cert.ps1
#   4. 按提示导入 CA 证书到受信任的根证书颁发机构
#
# 生成的文件:
#   - CodeSigningCA.cer      - CA 根证书 (需导入到 Windows 信任存储)
#   - HashTools_CodeSign.pfx - 代码签名证书 (用于 SignTool)

param(
    [string]$OutputDir = ".\certs",
    [string]$CompanyName = "Hash Tools Development",
    [System.Security.SecureString]$CertPassword,
    [int]$ValidityYears = 3
)

$ErrorActionPreference = "Stop"

# Prompt without echoing or persisting the PFX password. Automation can supply
# a SecureString obtained from its own secret store.
if ($null -eq $CertPassword) {
    $CertPassword = Read-Host "请输入 PFX 导出密码" -AsSecureString
}
if ($CertPassword.Length -eq 0) {
    throw "PFX 导出密码不能为空。"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Hash Tools 自签名证书生成工具" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# 创建输出目录
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "[+] 创建证书目录: $OutputDir" -ForegroundColor Green
}

# ========================================
# Step 1: 创建自签名 CA 根证书
# ========================================
Write-Host "`n[1/4] 创建 CA 根证书..." -ForegroundColor Yellow

$caSubject = "CN=$CompanyName Root CA, O=$CompanyName, C=CN"
$caExpiry = (Get-Date).AddYears($ValidityYears + 2)

# 创建 CA 证书
$caCert = New-SelfSignedCertificate `
    -Subject $caSubject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeyUsage CertSign, CRLSign, DigitalSignature `
    -KeyLength 4096 `
    -HashAlgorithm SHA256 `
    -NotAfter $caExpiry `
    -TextExtension @("2.5.29.19={critical}{text}ca=TRUE")

Write-Host "    CA 证书指纹: $($caCert.Thumbprint)" -ForegroundColor Gray

# 导出 CA 公钥证书 (.cer)
$caCerPath = Join-Path $OutputDir "CodeSigningCA.cer"
Export-Certificate -Cert $caCert -FilePath $caCerPath | Out-Null
Write-Host "[+] CA 证书已导出: $caCerPath" -ForegroundColor Green

# ========================================
# Step 2: 创建代码签名证书 (由 CA 签发)
# ========================================
Write-Host "`n[2/4] 创建代码签名证书..." -ForegroundColor Yellow

$codeSignSubject = "CN=$CompanyName Code Signing, O=$CompanyName, C=CN"
$codeSignExpiry = (Get-Date).AddYears($ValidityYears)

$codeSignCert = New-SelfSignedCertificate `
    -Subject $codeSignSubject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -Type CodeSigningCert `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -NotAfter $codeSignExpiry `
    -Signer $caCert `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")

Write-Host "    签名证书指纹: $($codeSignCert.Thumbprint)" -ForegroundColor Gray

# ========================================
# Step 3: 导出 PFX 文件 (含私钥)
# ========================================
Write-Host "`n[3/4] 导出 PFX 证书文件..." -ForegroundColor Yellow

$pfxPath = Join-Path $OutputDir "HashTools_CodeSign.pfx"
Export-PfxCertificate `
    -Cert $codeSignCert `
    -FilePath $pfxPath `
    -Password $CertPassword `
    -ChainOption BuildChain | Out-Null

Write-Host "[+] PFX 证书已导出: $pfxPath" -ForegroundColor Green

# ========================================
# Step 4: 创建签名批处理脚本
# ========================================
Write-Host "`n[4/4] 创建签名脚本..." -ForegroundColor Yellow

$signScript = @"
@echo off
REM Hash Tools 代码签名脚本
REM 使用方法: sign_exe.bat <要签名的EXE文件>
REM 使用当前用户证书存储中的证书；不在脚本中保存 PFX 密码。

set CERT_THUMBPRINT=$($codeSignCert.Thumbprint)
set TIMESTAMP_URL=http://timestamp.digicert.com

if "%~1"=="" (
    echo 用法: %~nx0 ^<EXE文件路径^>
    echo 示例: %~nx0 hash_tools.exe
    exit /b 1
)

echo.
echo [*] 签名文件: %~1
echo [*] 使用证书: %CERT_THUMBPRINT%
echo.

REM 使用 SignTool 签名
signtool sign /s My /sha1 "%CERT_THUMBPRINT%" /fd SHA256 /tr "%TIMESTAMP_URL%" /td SHA256 /v "%~1"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] 签名成功!
    echo.
    REM 验证签名
    signtool verify /pa /v "%~1"
) else (
    echo.
    echo [-] 签名失败! 错误代码: %ERRORLEVEL%
    echo.
    echo 常见问题:
    echo   1. 确保已安装 Windows SDK (包含 signtool.exe)
    echo   2. 确保 CA 证书已导入到 受信任的根证书颁发机构
    echo   3. 确保签名证书及私钥存在于当前用户的 My 证书存储中
)
"@

$signScriptPath = Join-Path $OutputDir "sign_exe.bat"
$signScript | Out-File -FilePath $signScriptPath -Encoding ASCII
Write-Host "[+] 签名脚本已创建: $signScriptPath" -ForegroundColor Green

# ========================================
# 完成提示
# ========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  证书创建完成!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n生成的文件:" -ForegroundColor White
Write-Host "  - $caCerPath" -ForegroundColor Gray
Write-Host "  - $pfxPath" -ForegroundColor Gray
Write-Host "  - $signScriptPath" -ForegroundColor Gray

Write-Host "`n下一步操作:" -ForegroundColor Yellow
Write-Host "  1. 双击 CodeSigningCA.cer" -ForegroundColor White
Write-Host "  2. 点击 '安装证书' -> '当前用户' -> '下一步'" -ForegroundColor White
Write-Host "  3. 选择 '将所有证书放入下列存储'" -ForegroundColor White
Write-Host "  4. 点击 '浏览' -> 选择 '受信任的根证书颁发机构'" -ForegroundColor White
Write-Host "  5. 完成安装" -ForegroundColor White

Write-Host "`n签名程序:" -ForegroundColor Yellow
Write-Host "  cd $OutputDir" -ForegroundColor White
Write-Host "  .\sign_exe.bat ..\target\release\hash_tools.exe" -ForegroundColor White

Write-Host "`n证书信息:" -ForegroundColor Yellow
Write-Host "  CA 证书有效期: 至 $($caExpiry.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  签名证书有效期: 至 $($codeSignExpiry.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host "  PFX 密码不会写入文件或日志，请自行安全保管。" -ForegroundColor White

Write-Host "`n" -ForegroundColor White

# 清理 - 从证书存储中删除 (可选)
Write-Host "提示: 证书已保留在 Windows 证书存储中 (Cert:\CurrentUser\My)" -ForegroundColor DarkGray
Write-Host "如需清理,可执行: Remove-Item Cert:\CurrentUser\My\$($codeSignCert.Thumbprint)" -ForegroundColor DarkGray
