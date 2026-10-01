# Releasing 2.x

The `release/1.x` branch and 1.x tags preserve the legacy packages. The 2.x
source of truth is `main`. Both packages use the same version.

## One-time NuGet setup

In the `dbalikhin` NuGet.org account, add a Trusted Publishing policy for
GitHub owner `dotnetarium`, repository `dotnetarium`, workflow file
`publish.yml`, with no environment. Allow publishing new packages and new
versions for `Dotnetarium*`. This covers `Dotnetarium.Analyzers` and
`dotnetarium` without a stored API key.

## Release

1. Set the same version in `Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj`
   and `Dotnetarium.Tool/Dotnetarium.Tool.csproj`, and update the installation
   examples in the root README. Merge the change to `main` after CI passes.
2. Tag that commit `v<version>`, such as `v2.0.0`.
3. Publish a GitHub release for that tag. Keep the description to short
   **Features** and **Bug fixes** bullets, any essential upgrade note, and a
   full changelog link.
4. The release workflow checks the tag, tests and packs both packages,
   installs them in the CLI smoke test, publishes them to NuGet.org, and adds
   the `.nupkg` files to the GitHub release. Verify both package pages and a
   fresh `dotnet tool install --global dotnetarium` after indexing.
5. After the new packages are available, deprecate the 1.x package IDs on
   NuGet.org as legacy and point each one to its 2.x replacement. Leave the
   old packages listed so existing consumers can still find them.
