$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$feed = Join-Path $root 'artifacts'
if (-not (Test-Path -LiteralPath (Join-Path $feed 'dotnetarium-scs.2.0.0-alpha.1.nupkg'))) {
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
& dotnet restore $project --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'CLI fixture restore failed.' }

& dotnet tool install dotnetarium-scs --version 2.0.0-alpha.1 --tool-path $toolPath --add-source $feed --ignore-failed-sources --no-cache
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

'Global tool package, default rules, custom JSON, and relative SARIF checks passed.' | Write-Output
exit 0
