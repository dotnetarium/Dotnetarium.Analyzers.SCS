$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
$analyzerSpec = [xml](Get-Content -LiteralPath (Join-Path $root 'Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj') -Raw)
$toolSpec = [xml](Get-Content -LiteralPath (Join-Path $root 'Dotnetarium.Tool/Dotnetarium.Tool.csproj') -Raw)
$analyzerVersion = $analyzerSpec.SelectSingleNode('//PackageVersion').InnerText
$toolVersion = $toolSpec.SelectSingleNode('//Version').InnerText
if (-not (Test-Path -LiteralPath (Join-Path $feed "dotnetarium.$toolVersion.nupkg")) -or
    -not (Test-Path -LiteralPath (Join-Path $feed "Dotnetarium.Analyzers.$analyzerVersion.nupkg"))) {
    throw 'Pack both 2.x packages into artifacts before running this smoke check.'
}

$scratch = Join-Path $env:TEMP ('dotnetarium-cli-smoke-' + [guid]::NewGuid().ToString('N'))
$toolPath = Join-Path $scratch 'tool'
$projectPath = Join-Path $scratch 'project'
New-Item -ItemType Directory -Path $scratch, $toolPath, $projectPath -Force | Out-Null
$env:NUGET_PACKAGES = Join-Path $scratch 'packages'

& dotnet new classlib -n CliSmoke -o $projectPath --force --no-restore | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create CLI fixture.' }
@'
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using Dapper;
using Npgsql;

public class Demo
{
    public async Task RunAsync()
    {
        var input = Console.ReadLine();
        Process.Start(input!);
        using var client = new HttpClient();
        await client.GetStringAsync(input);
        using var connection = new NpgsqlConnection();
        _ = connection.Query(input!);
        _ = new NpgsqlCommand(input);
        var settings = new Newtonsoft.Json.JsonSerializerSettings
        {
            TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All
        };
        new Custom().Execute(input!);
    }
}

public class Custom
{
    public void Execute(string query) { }
}

namespace Newtonsoft.Json
{
    public enum TypeNameHandling { None, All }
    public sealed class JsonSerializerSettings
    {
        public TypeNameHandling TypeNameHandling { get; set; }
    }
}
'@ | Set-Content -LiteralPath (Join-Path $projectPath 'Unsafe Input.cs') -Encoding utf8
$project = Join-Path $projectPath 'CliSmoke.csproj'
$projectXml = Get-Content -LiteralPath $project -Raw
$packageReference = "  <ItemGroup><PackageReference Include=`"Dotnetarium.Analyzers`" Version=`"$analyzerVersion`" /><PackageReference Include=`"Dapper`" Version=`"2.1.79`" /><PackageReference Include=`"Npgsql`" Version=`"10.0.3`" /></ItemGroup>"
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
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0001') -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0008') -or -not ($buildOutput -match 'DNA0011')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 10 findings.'
}

& dotnet tool install dotnetarium --version $toolVersion --tool-path $toolPath --add-source $feed --ignore-failed-sources --no-cache
if ($LASTEXITCODE -ne 0) { throw 'Local global tool install failed.' }
$tool = Join-Path $toolPath 'dotnetarium.exe'
$help = & $tool --help
if ($LASTEXITCODE -ne 0 -or -not ($help -match '--sarif') -or
    -not ($help -match '--fail-on-findings') -or
    ($help -match '--sdk-path|--sarif-absolute-paths|--cwe|--export|--fail-any-warn')) {
    throw 'CLI help does not match the simplified options.'
}
$sarif = Join-Path $scratch 'results.sarif'
$scanOutput = & $tool $project --sarif $sarif --fail-on-findings
if ($LASTEXITCODE -ne 1) { throw 'CLI did not report security findings with exit code 1.' }
if (-not ($scanOutput -match 'CWE-')) { throw 'Console findings omitted default CWE groups.' }
$report = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
$ids = @($report.runs[0].results | ForEach-Object ruleId)
if (@($ids | Where-Object { $_ -eq 'DNA0001' }).Count -ne 2 -or
    @($ids | Where-Object { $_ -eq 'DNA0002' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0008' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0011' }).Count -ne 1) {
    throw ('Unexpected default CLI rules: ' + ($ids -join ', '))
}
foreach ($result in $report.runs[0].results) {
    if ($result.locations[0].physicalLocation.artifactLocation.uri -ne 'Unsafe%20Input.cs' -or
        $result.locations[0].physicalLocation.artifactLocation.uriBaseId -ne '%SRCROOT%' -or
        $result.PSObject.Properties.Name -contains 'relatedLocations' -or
        ($result.ruleId -ne 'DNA0008' -and @($result.codeFlows).Count -ne 1)) {
        throw ('Invalid relative path or engine flow for ' + $result.ruleId)
    }
    if ($report.runs[0].tool.driver.rules[$result.ruleIndex].id -ne $result.ruleId) {
        throw ('Finding does not reference its rule definition: ' + $result.ruleId)
    }
}
$ruleIds = @($report.runs[0].tool.driver.rules | ForEach-Object id)
if (@($ruleIds | Sort-Object -Unique).Count -ne $ruleIds.Count) {
    throw 'SARIF repeats a rule definition.'
}
$flow = @($report.runs[0].results | Where-Object ruleId -eq 'DNA0001')[0].codeFlows[0].threadFlows[0].locations
if ($flow.Count -lt 2 -or $flow[0].location.id -ne 1 -or
    $flow[-1].location.physicalLocation.artifactLocation.uri -ne 'Unsafe%20Input.cs') {
    throw 'SARIF flow steps are missing stable locations.'
}

# The same analyzer package and .NET 10-hosted tool must also scan .NET 8 code.
$projectXml = Get-Content -LiteralPath $project -Raw
$projectXml.Replace('<TargetFramework>net10.0</TargetFramework>',
    '<TargetFramework>net8.0</TargetFramework>') |
    Set-Content -LiteralPath $project -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw '.NET 8 fixture restore failed.' }
$buildOutput = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0001') -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0008') -or -not ($buildOutput -match 'DNA0011')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 8 findings.'
}
& $tool $project --fail-on-findings | Out-Null
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
$customOutput = & $tool $project --config $config
if ($LASTEXITCODE -ne 0 -or -not ($customOutput -match 'DNA0001')) {
    throw 'CLI did not load the custom JSON sink.'
}

$bad = Join-Path $scratch 'bad.json'
'{"Version":"2.0","Sinkz":[]}' | Set-Content -LiteralPath $bad -Encoding utf8
$badOutput = & $tool $project --config $bad 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($badOutput -match 'Invalid Dotnetarium.json')) {
    throw 'CLI did not reject an invalid JSON rule field.'
}

Add-Content -LiteralPath (Join-Path $projectPath 'Unsafe Input.cs') -Value 'class Broken { MissingType value; }'
$incompleteSarif = Join-Path $scratch 'incomplete.sarif'
$invalidProjectOutput = & $tool $project --sarif $incompleteSarif 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($invalidProjectOutput -match 'CS0246') -or
    -not ($invalidProjectOutput -match 'Scan incomplete') -or
    (Test-Path -LiteralPath $incompleteSarif)) {
    throw 'CLI did not explain incomplete scanning of a project with compiler errors.'
}

'Analyzer NuGet package and global tool scan .NET 8/10; custom JSON, relative SARIF, and compiler error checks passed.' | Write-Output
exit 0
