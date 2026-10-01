# Dotnetarium.Analyzers.SCS
Static code analyzer for .NET (Nuget package) based on Security Code Scan.

## Installation
It is a [Nuget package](https://www.nuget.org/packages/Dotnetarium.Analyzers.SCS)
Add the following package to your project `Dotnetarium.Analyzers.SCS`

## Notes
Dotnetarium.Analyzers.SCS is still using the SecurityCodeScan website to provide references for fixes.

## How to add a new analyzer/rule
In most cases, you will want to simply add a new source, sink, sanitizer to existing ruleset. Or probably just a new sink.
Check `Config/Main.yml` file.

### Key Concept
#### Entry Points
Entry points are the methods or classes where untrusted data enters the application. These are typically public methods in controllers or API endpoints in web applications.

#### Sources
Sources are the origins of potentially tainted data. They include objects or methods that return data from external or untrusted inputs, such as HTTP requests.

#### Sinks
Sinks are the points in the application where tainted data could potentially cause harm if not properly sanitized. These often include database queries, file writes, or any other operation that executes or displays untrusted data.

#### Sanitizers
Sanitizers are methods or functions that cleanse tainted data, making it safe for use in sinks. They transform, encode, or otherwise neutralize harmful data.

[Read more about rule configuration](docs/RuleConfiguration.md)

## Compatibility

The analyzer uses Roslyn 4.14.0 and requires Visual Studio 2022 version 17.14 or newer. It supports projects targeting .NET 8 and .NET 10 when built with a compatible SDK; .NET 10 projects require the .NET 10 SDK or Visual Studio 2026.
See the [Roslyn compatibility table](https://learn.microsoft.com/en-us/visualstudio/extensibility/roslyn-version-support).

## Contributing
If you would like to contribute to DotnetariumSCS, please fork the repository and submit a pull request. For major changes, please open an issue to discuss what you would like to change.

## License
DotnetariumSCS is licensed under the LGPL License. See the LICENSE file for more information.

## Contact
For support or any inquiries, please open an issue on GitHub
