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

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ('dotnetarium-cli-smoke-' + [guid]::NewGuid().ToString('N'))
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
using System.Net.Security;
using System.Net.WebSockets;
using Microsoft.Extensions.Hosting;
using System.IO;
using System.IO.Pipelines;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Dapper;
using Npgsql;
using Azure.Messaging.ServiceBus;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;

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
        _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
        _ = new SocketsHttpHandler { SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true } };
        _ = new SslStream(new MemoryStream(), false, (_, _, _, _) => true);
        var socket = new ClientWebSocket();
        socket.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, errors) => errors == SslPolicyErrors.None };
    }
}

public static class DevelopmentTls
{
    public static void Configure(IHostEnvironment environment)
    {
        if (environment.IsDevelopment())
            _ = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
    }
}
public class Custom
{
    public void Execute(string query) { }
}

public sealed class HubService { public string Command => "fixed"; }
public sealed class BodyInput { public string Command { get; set; } = ""; }
public sealed class InputHub : Hub
{
    public void Execute(string command, HubService service)
    {
        Process.Start(command);
        Process.Start(service.Command);
    }
    public async Task Upload(IAsyncEnumerable<string> stream)
    {
        await foreach (var command in stream) Process.Start(command);
    }
}
public sealed class FunctionInput
{
    [Function("http")]
    public async Task Http([HttpTrigger] HttpRequestData request,
        [Microsoft.Azure.Functions.Worker.Http.FromBody] BodyInput body)
    {
        Process.Start(await request.ReadAsStringAsync());
        Process.Start(body.Command);
        Process.Start(request.FunctionContext.InvocationId);
    }
    [Function("bus")]
    public void Bus([ServiceBusTrigger("queue")] ServiceBusReceivedMessage message,
        ServiceBusMessageActions actions, HubService service)
    {
        Process.Start(message.Body.ToString());
        Process.Start(actions.ToString());
        Process.Start(service.Command);
    }
}
public static class NetworkInput
{
    public static async Task Run(HttpContext context)
    {
        var socket = await context.WebSockets.AcceptWebSocketAsync();
        var bytes = new byte[128];
        await socket.ReceiveAsync(bytes.AsMemory(), default);
        Process.Start(Encoding.UTF8.GetString(bytes));
        var result = await context.Request.BodyReader.ReadAsync();
        Process.Start(Encoding.UTF8.GetString(result.Buffer.ToArray()));
        if (context.Request.BodyReader.TryRead(out var available))
            Process.Start(Encoding.UTF8.GetString(available.Buffer.ToArray()));
        var local = new Pipe();
        var safe = await local.Reader.ReadAsync();
        Process.Start(Encoding.UTF8.GetString(safe.Buffer.ToArray()));
    }
}
public static class HubRegistration
{
    public static void Configure(IServiceCollection services)
    {
        services.AddSingleton<HubService>();
        services.AddSignalR();
    }
    public static void Map(IEndpointRouteBuilder endpoints) => endpoints.MapHub<InputHub>("/input");
    public static void MapBody(WebApplication app)
    {
        app.MapPost("/body", (BodyInput body) => Process.Start(body.Command));
        app.MapPost("/upload", (IFormFile file) => Process.Start(file.FileName));
        app.MapPost("/service", (HubService service) => Process.Start(service.Command));
    }
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
$packageReference = "  <ItemGroup><FrameworkReference Include=`"Microsoft.AspNetCore.App`" /><PackageReference Include=`"Dotnetarium.Analyzers`" Version=`"$analyzerVersion`" /><PackageReference Include=`"Microsoft.Azure.Functions.Worker.Core`" Version=`"2.52.0`" /><PackageReference Include=`"Microsoft.Azure.Functions.Worker.Extensions.Http`" Version=`"3.3.0`" /><PackageReference Include=`"Microsoft.Azure.Functions.Worker.Extensions.ServiceBus`" Version=`"5.24.0`" /><PackageReference Include=`"Dapper`" Version=`"2.1.79`" /><PackageReference Include=`"Npgsql`" Version=`"10.0.3`" /></ItemGroup>"
$projectXml.Replace('</Project>', "$packageReference`n</Project>") |
    Set-Content -LiteralPath $project -Encoding utf8
$nugetConfig = Join-Path $scratch 'NuGet.Config'
@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources><clear /><add key="local" value="$feed" /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources>
  <packageSourceMapping>
    <packageSource key="local"><package pattern="Dotnetarium*" /></packageSource>
    <packageSource key="nuget.org"><package pattern="*" /></packageSource>
  </packageSourceMapping>
</configuration>
"@ | Set-Content -LiteralPath $nugetConfig -Encoding utf8
& dotnet restore $project --configfile $nugetConfig --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'CLI fixture restore failed.' }
$buildOutput = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or -not ($buildOutput -match 'DNA0001') -or -not ($buildOutput -match 'DNA0002') -or
    -not ($buildOutput -match 'DNA0008') -or -not ($buildOutput -match 'DNA0011') -or -not ($buildOutput -match 'DNA0020')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 10 findings.'
}

& dotnet tool install dotnetarium --version $toolVersion --tool-path $toolPath --configfile $nugetConfig --ignore-failed-sources --no-cache
if ($LASTEXITCODE -ne 0) { throw 'Local global tool install failed.' }
$tool = Join-Path $toolPath $(if ($IsWindows) { 'dotnetarium.exe' } else { 'dotnetarium' })
$help = & $tool --help
if ($LASTEXITCODE -ne 0 -or -not ($help -match '\.slnx') -or -not ($help -match '--sarif') -or
    -not ($help -match '--fail\b') -or
    ($help -match '--sdk-path|--sarif-absolute-paths|--cwe|--export|--fail-any-warn|--fail-on-findings')) {
    throw 'CLI help does not match the simplified options.'
}
$sarif = Join-Path $scratch 'results.sarif'
$launcher = Join-Path $scratch 'launcher'
New-Item -ItemType Directory -Path $launcher | Out-Null
'{"sdk":{"version":"8.0.100","rollForward":"disable"}}' |
    Set-Content -LiteralPath (Join-Path $launcher 'global.json') -Encoding utf8
Push-Location $launcher
try {
    $scanOutput = & $tool $project --sarif $sarif --fail
    $scanExitCode = $LASTEXITCODE
} finally {
    Pop-Location
}
if ($scanExitCode -ne 1) { throw 'CLI did not scan from a directory with a different SDK pin.' }
if (-not ($scanOutput -match 'CWE-')) { throw 'Console findings omitted default CWE groups.' }
$report = Get-Content -LiteralPath $sarif -Raw | ConvertFrom-Json
$ids = @($report.runs[0].results | ForEach-Object ruleId)
if (@($ids | Where-Object { $_ -eq 'DNA0001' }).Count -ne 2 -or
    @($ids | Where-Object { $_ -eq 'DNA0002' }).Count -ne 11 -or
    @($ids | Where-Object { $_ -eq 'DNA0008' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0011' }).Count -ne 1 -or
    @($ids | Where-Object { $_ -eq 'DNA0020' }).Count -ne 4) {
    throw ('Unexpected default CLI rules: ' + ($ids -join ', '))
}
foreach ($result in $report.runs[0].results) {
    if ($result.locations[0].physicalLocation.artifactLocation.uri -ne 'Unsafe%20Input.cs' -or
        $result.locations[0].physicalLocation.artifactLocation.uriBaseId -ne '%SRCROOT%' -or
        $result.PSObject.Properties.Name -contains 'relatedLocations' -or
        ($result.ruleId -notin @('DNA0008', 'DNA0020') -and @($result.codeFlows).Count -ne 1)) {
        throw ('Invalid relative path or engine flow for ' + $result.ruleId)
    }
    if ($report.runs[0].tool.driver.rules[$result.ruleIndex].id -ne $result.ruleId) {
        throw ('Finding does not reference its rule definition: ' + $result.ruleId)
    }
}
$ruleIds = @($report.runs[0].tool.driver.rules | ForEach-Object id)
$tlsRules = @($report.runs[0].tool.driver.rules | Where-Object id -eq 'DNA0020')
if ($tlsRules.Count -ne 1 -or $tlsRules[0].defaultConfiguration.level -ne 'warning' -or
    $tlsRules[0].properties.tags -notcontains 'CWE-295') {
    throw 'TLS configuration findings must reference one warning rule with CWE-295 metadata.'
}
foreach ($result in @($report.runs[0].results | Where-Object ruleId -eq 'DNA0020')) {
    if ($result.PSObject.Properties.Name -contains 'codeFlows') {
        throw 'A TLS configuration finding must not invent a source-to-sink flow.'
    }
}
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
    -not ($buildOutput -match 'DNA0008') -or -not ($buildOutput -match 'DNA0011') -or -not ($buildOutput -match 'DNA0020')) {
    $buildOutput | Write-Output
    throw 'Packaged analyzer did not report the expected .NET 8 findings.'
}
$net8Sarif = Join-Path $scratch 'results-net8.sarif'
& $tool $project --sarif $net8Sarif --fail | Out-Null
if ($LASTEXITCODE -ne 1) { throw 'Global tool did not find the .NET 8 flows.' }
$net8Report = Get-Content -LiteralPath $net8Sarif -Raw | ConvertFrom-Json
$net8Ids = @($net8Report.runs[0].results | ForEach-Object ruleId)
if (Compare-Object ($ids | Sort-Object) ($net8Ids | Sort-Object)) {
    throw '.NET 8 and .NET 10 fixtures must report the same source-to-sink flows.'
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
Copy-Item -LiteralPath $config -Destination (Join-Path $projectPath 'dotnetarium.json')
$configuredBuild = & dotnet build $project --no-restore --nologo -v quiet -p:UseSharedCompilation=false 2>&1
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($configuredBuild -join "`n"), 'DNA0001')).Count -lt 3) {
    $configuredBuild | Write-Output
    throw 'Packaged analyzer did not include lowercase dotnetarium.json automatically.'
}
$customOutput = & $tool $project
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($customOutput -join "`n"), 'DNA0001')).Count -ne 3) {
    throw 'CLI did not discover lowercase dotnetarium.json.'
}
$override = Join-Path $scratch 'override.json'
'{"Version":"2.0","Sinks":[]}' | Set-Content -LiteralPath $override -Encoding utf8
$overrideOutput = & $tool $project --config $override
if ($LASTEXITCODE -ne 0 -or ([regex]::Matches(($overrideOutput -join "`n"), 'DNA0001')).Count -ne 2) {
    throw 'Explicit --config did not override the project config.'
}

$bad = Join-Path $scratch 'bad.json'
'{"Version":"2.0","Sinkz":[]}' | Set-Content -LiteralPath $bad -Encoding utf8
$badOutput = & $tool $project --config $bad 2>&1
if ($LASTEXITCODE -ne 2 -or -not ($badOutput -match 'Invalid dotnetarium.json')) {
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
