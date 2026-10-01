$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
$analyzerSpec = [xml](Get-Content -LiteralPath (Join-Path $root 'DotnetariumSCS/DotnetariumSCS.csproj') -Raw)
$toolSpec = [xml](Get-Content -LiteralPath (Join-Path $root 'Dotnetarium.Tool/Dotnetarium.Tool.csproj') -Raw)
$analyzerVersion = $analyzerSpec.SelectSingleNode('//PackageVersion').InnerText
$toolVersion = $toolSpec.SelectSingleNode('//Version').InnerText
if (-not (Test-Path -LiteralPath (Join-Path $feed "dotnetarium-scs.$toolVersion.nupkg")) -or
    -not (Test-Path -LiteralPath (Join-Path $feed "Dotnetarium.Analyzers.SCS.$analyzerVersion.nupkg"))) {
    throw 'Pack both 2.x packages into artifacts before running this smoke check.'
}

$scratch = Join-Path $env:TEMP ('dotnetarium-cli-smoke-' + [guid]::NewGuid().ToString('N'))
$toolPath = Join-Path $scratch 'tool'
$projectPath = Join-Path $scratch 'project'
New-Item -ItemType Directory -Path $scratch, $toolPath, $projectPath -Force | Out-Null

& dotnet new classlib -n CliSmoke -o $projectPath --force --no-restore | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create CLI fixture.' }
@'
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;

public class Demo
{
    public async Task RunAsync()
    {
        var input = Console.ReadLine();
        Process.Start(input!);
        using var client = new HttpClient();
        await client.GetStringAsync(input);
        new Custom().Execute(input!);
    }
}

public class Custom
{
    public void Execute(string query) { }
}
'@ | Set-Content -LiteralPath (Join-Path $projectPath 'Class1.cs') -Encoding utf8
$project = Join-Path $projectPath 'CliSmoke.csproj'
$projectXml = Get-Content -LiteralPath $project -Raw
$packageReference = "  <ItemGroup><PackageReference Include=`"Dotnetarium.Analyzers.SCS`" Version=`"$analyzerVersion`" /></ItemGroup>"
$projectXml.Replace('</Project>', "$packageReference`n</Project>") |
    Set-Content -LiteralPath $project -Encoding utf8
$nugetConfig = Join-Path $scratch 'NuGet.Config'
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /><add key="local" value="$feed" /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>
"@ | Set-Content -LiteralPath $nugetConfig -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'CLI fixture restore failed.' }
$buildOutput = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0011')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 10 findings.'
}

& dotnet tool install dotnetarium-scs --version $toolVersion --tool-path $toolPath --add-source $feed --ignore-failed-sources --no-cache
if ($LASTEXITCODE -ne 0) { throw 'Local global tool install failed.' }
$tool = Join-Path $toolPath 'dotnetarium-scs.exe'
$sdkRoot = Split-Path (Get-Command dotnet).Source -Parent
$sdkVersion = (& dotnet --version).Trim()
$sdkPath = Join-Path $sdkRoot ('sdk/' + $sdkVersion)
$sarif = Join-Path $scratch 'results.sarif'
& $tool $project --sdk-path $sdkPath --sarif $sarif --fail-any-warn | Out-Null
if ($LASTEXITCODE -ne 1) { throw 'CLI did not report security findings with exit code 1.' }
$report = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
$ids = @($report.runs[0].results | ForEach-Object ruleId)
if (@($ids | Where-Object { $_ -eq 'DNA0002' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0011' }).Count -ne 1) {
    throw ('Unexpected default CLI rules: ' + ($ids -join ', '))
}
foreach ($result in $report.runs[0].results) {
    if ($result.locations[0].physicalLocation.artifactLocation.uri -ne 'Class1.cs' -or
        @($result.codeFlows).Count -ne 1) {
        throw ('Missing relative path or engine flow for ' + $result.ruleId)
    }
}

# The same analyzer package and .NET 10-hosted tool must also scan .NET 8 code.
$projectXml = Get-Content -LiteralPath $project -Raw
$projectXml.Replace('<TargetFramework>net10.0</TargetFramework>',
    '<TargetFramework>net8.0</TargetFramework>') |
    Set-Content -LiteralPath $project -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw '.NET 8 fixture restore failed.' }
$buildOutput = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0011')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 8 findings.'
}
& $tool $project --sdk-path $sdkPath --fail-any-warn | Out-Null
if ($LASTEXITCODE -ne 1) { throw 'Global tool did not find the .NET 8 flows.' }

$config = Join-Path $scratch 'custom.json'
@'
{
  "Version": "2.0",
  "Sinks": [
    {
      "Type": "Custom",
      "TaintTypes": ["SqlInjection"],
      "Methods": [{ "Name": "Execute", "Arguments": ["query"] }]
    }
  ]
}
'@ | Set-Content -LiteralPath $config -Encoding utf8
$customOutput = & $tool $project --sdk-path $sdkPath --config $config
if ($LASTEXITCODE -ne 0 -or -not ($customOutput -match 'DNA0001')) {
    throw 'CLI did not load the custom JSON sink.'
}

$bad = Join-Path $scratch 'bad.json'
'{"Version":"2.0","Sinkz":[]}' | Set-Content -LiteralPath $bad -Encoding utf8
$badOutput = & $tool $project --sdk-path $sdkPath --config $bad 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($badOutput -match 'Invalid Dotnetarium.json')) {
    throw 'CLI did not reject an invalid JSON rule field.'
}

Add-Content -LiteralPath (Join-Path $projectPath 'Class1.cs') -Value 'class Broken { MissingType value; }'
$incompleteSarif = Join-Path $scratch 'incomplete.sarif'
$invalidProjectOutput = & $tool $project --sdk-path $sdkPath --sarif $incompleteSarif 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($invalidProjectOutput -match 'CS0246') -or
    -not ($invalidProjectOutput -match 'Scan incomplete') -or
    (Test-Path -LiteralPath $incompleteSarif)) {
    throw 'CLI did not explain incomplete scanning of a project with compiler errors.'
}

'Analyzer NuGet package and global tool scan .NET 8/10; custom JSON, relative SARIF, and compiler error checks passed.' | Write-Output
exit 0
