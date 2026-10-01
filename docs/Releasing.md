# Releasing 2.x

The `release/1.x` branch and 1.x tags preserve the legacy packages. The 2.x
source of truth is `main`. Both packages use the same version.

## One-time NuGet setup

1. In GitHub repository settings, create the `nuget-publish` environment.
   Restrict deployments to `v2.*` tags. Add yourself as a required reviewer and
   leave **Prevent self-review** off, so you can approve your own release through
   **Review deployments**. Keep administrator bypass available as a recovery
   option; routine releases can use the normal approval button.
2. In the `dbalikhin` NuGet.org account, add a Trusted Publishing policy with:
   GitHub owner `dotnetarium`, repository `dotnetarium`, workflow file
   `publish.yml` (filename only), and environment `nuget-publish`. Enter that
   environment value so the policy matches the publishing job.
3. Allow publishing new packages and new versions for `Dotnetarium*`. The
   pattern covers `Dotnetarium.Analyzers` and `dotnetarium`. No NuGet API key
   secret is needed.

## Release

1. Set the same version in `Dotnetarium.Analyzers/Dotnetarium.Analyzers.csproj`
   and `Dotnetarium.Tool/Dotnetarium.Tool.csproj`, and update the installation
   examples in the root README. Merge the change to `main` after CI passes.
2. Tag that merged commit `v<version>`, such as `v2.0.0`. Verify the tag
   points to the release commit before publishing the GitHub release.
3. Publish a GitHub release for that tag. Keep the description to short
   **Features** and **Bug fixes** bullets, any essential upgrade note, and a
   full changelog link.
4. The release workflow checks the tag, tests and packs both packages, then
   waits for your approval of the `nuget-publish` environment. The publishing job
   obtains a short-lived NuGet credential, publishes both packages, and adds
   the `.nupkg` files to the GitHub release. Verify both package pages and a
   fresh `dotnet tool install --global dotnetarium` after indexing.
5. After the new packages are available, deprecate the 1.x package IDs on
   NuGet.org as legacy and point each one to its 2.x replacement. Leave the
   old packages listed so existing consumers can still find them.
