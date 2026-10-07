param([string]$SdkPath = $env:SGXSDKInstallPath)
$ErrorActionPreference = 'Stop'
if (-not $SdkPath) { $SdkPath = Join-Path $env:USERPROFILE 'Downloads\Intel_SGX_SDK_for_Windows\nuget_extracted\build\native' }
$SdkPath = (Resolve-Path -LiteralPath $SdkPath).Path.TrimEnd('\') + '/'
if (-not (Test-Path -LiteralPath ($SdkPath + 'bin/win32/release/sgx_edger8r.exe'))) { throw 'Use -SdkPath to specify the SDK build/native directory' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -version '[16.0,17.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual Studio 2019 C++ tools not found' }
$msbuild = Join-Path ($vs | Select-Object -First 1) 'MSBuild\Current\Bin\MSBuild.exe'
& $msbuild (Join-Path $PSScriptRoot 'LR3.sln') /t:Build /m /nologo /v:minimal /p:Configuration=Simulation /p:Platform=x64 "/p:SGXSDKInstallPath=$SdkPath" 2>&1 | Tee-Object -FilePath (Join-Path $PSScriptRoot 'analysis\logs\stage23_build.txt')
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
foreach ($dllName in @('sgx_urts_simd.dll','sgx_uae_service_sim.dll','sgx_epid_sim.dll','sgx_launch_sim.dll','sgx_platform_sim.dll','sgx_quote_ex_sim.dll')) {
    Copy-Item -LiteralPath ($SdkPath + 'bin/x64/Release/' + $dllName) -Destination (Join-Path $PSScriptRoot ('build\bin\' + $dllName))
}
& $msbuild (Join-Path $PSScriptRoot 'stage1\table_app.vcxproj') /t:Build /nologo /v:minimal /p:Configuration=Simulation /p:Platform=x64 2>&1 | Tee-Object -FilePath (Join-Path $PSScriptRoot 'analysis\logs\stage1_build_msvc.txt')
if ($LASTEXITCODE -ne 0) { throw 'Stage 1 build failed' }
Write-Host 'Build and runtime deployment completed: build\bin\app.exe and table_app.exe'
