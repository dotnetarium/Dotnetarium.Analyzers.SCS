$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$scratch = Join-Path $env:TEMP ('dotnetarium-razor-smoke-' + [guid]::NewGuid().ToString('N'))
$feed = Join-Path $scratch 'feed'
$packages = Join-Path $scratch 'packages'
New-Item -ItemType Directory -Path $feed, $packages -Force | Out-Null

$analyzer = Join-Path $root 'DotnetariumSCS/DotnetariumSCS.csproj'
& dotnet build $analyzer -c Release --nologo -v quiet -clp:ErrorsOnly -p:PackageVersion=0.0.0-razor-smoke
if ($LASTEXITCODE -ne 0) { throw 'Analyzer build failed.' }
& dotnet pack $analyzer -c Release --no-build --nologo -v quiet -p:PackageVersion=0.0.0-razor-smoke -o $feed
if ($LASTEXITCODE -ne 0) { throw 'Analyzer package build failed.' }

$config = Join-Path $scratch 'NuGet.Config'
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /><add key="local" value="$feed" /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>
"@ | Set-Content -LiteralPath $config
$env:NUGET_PACKAGES = $packages

$client = Join-Path $PSScriptRoot 'Client/Client.csproj'
$server = Join-Path $PSScriptRoot 'Server/Server.csproj'
& dotnet restore $server --configfile $config --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Razor fixture restore failed.' }

$diagnostics = @()
foreach ($project in @($client, $server)) {
    $output = & dotnet build $project -c Release --no-restore --nologo -v quiet -p:UseSharedCompilation=false -p:BuildProjectReferences=false 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | Write-Output
        throw "Razor fixture build failed: $project"
    }
    foreach ($line in $output) {
        if ($line -match '([^\\/]+\.(?:razor|cshtml|cs))\((\d+),\d+\): warning (SCS\d+)') {
            $diagnostics += "$($Matches[1]):$($Matches[2]):$($Matches[3])"
        }
    }
}

$actual = @($diagnostics | Sort-Object -Unique)
$expected = @(
    'ClientProbe.razor:3:SCS0029',
    'AutoProbe.razor:3:SCS0029',
    'AutoProbe.razor:4:SCS0029',
    'ManualComponent.cs:13:SCS0029',
    'ManualComponent.cs:14:SCS0029',
    'ManualComponent.cs:15:SCS0029',
    'ServerProbe.razor:3:SCS0029',
    'ServerProbe.razor:4:SCS0029',
    'FormProbe.razor:2:SCS0029',
    'RouteProbe.razor:2:SCS0029',
    'RawPage.cshtml:3:SCS0029'
) | Sort-Object

if (Compare-Object $expected $actual) {
    "Expected: $($expected -join ', ')" | Write-Output
    "Actual: $($actual -join ', ')" | Write-Output
    throw 'Razor diagnostics differ from expected sources, sinks, or safe controls.'
}

'Razor, Blazor render mode, and safe-output smoke checks passed.' | Write-Output
