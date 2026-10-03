# Validation and taint precision

Validation only protects a sink when its result controls the branch using the
same stable value. Ignored checks, unrelated values, assignments between the
check and the sink, ref/out escapes, and checks outside a deferred callback do
not suppress findings.

- Redirects: exact framework `IsLocalUrl` checks support successful branches,
  `&&` conditions and simple rejecting return/throw guard clauses. Prefer
  `LocalRedirect` when the destination is intended to be local.
- Finite allowlists: equality to a constant string, or `Enumerable.Contains` on
  an inline constant string array, can bound a value in the consuming branch.
- File paths: a stable `Path.GetFullPath` result checked with
  `StartsWith(absoluteConstantRootWithTrailingSeparator, StringComparison.Ordinal)`
  is recognized. A textual prefix without canonicalization or the separator
  boundary is insufficient. This is lexical containment; symlinks, mount changes
  and time-of-check/time-of-use races still require application controls.
- Outbound requests: a complete literal HTTP(S) origin ending in `/`, followed
  by an untrusted path/query suffix, does not imply attacker control of the
  authority. A partial host prefix and `BaseAddress` alone are insufficient:
  absolute URLs and network-path references can override a base URI. Redirects
  and DNS/address policy still need runtime validation.

Example path check:

```csharp
var path = Path.GetFullPath(input);
if (!path.StartsWith("/srv/uploads/", StringComparison.Ordinal))
    throw new ArgumentException("Outside the upload directory");
File.ReadAllText(path);
```

These are deliberately narrow proofs. Arbitrary helper validators, mutable
allowlist collections, platform-specific normalization and complex guard
clauses may still produce review candidates. Use a targeted suppression with a
reason after verifying the runtime invariant; do not declare broad validators
as unconditional sanitizers.

Writable `Memory`, `Span`, and `ArraySegment` views share taint with their backing
array. Aliases, view reassignment, and control-flow branches are tracked. Replacing
an array variable with a distinct allocation does not transfer the old array's
taint. Unknown buffer factories are not guessed.
