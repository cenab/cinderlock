# Discovery proposals

`discover.Propose(ctx, root)` returns reviewable offline configuration patches.
It reads local files and never applies changes. The existing `discover.Scan`
API and `scan` command keep their existing behavior. Write optional proposals
with `cinderlock scan DIRECTORY --proposals-out /private/proposals.json`, or use
the Go API in [internal/discover](../internal/discover/). The command never applies
a patch. Keep the new report outside the application source tree.

> **Note:** This is a preview feature currently under active development.

Review each proposal, preload the required artifacts, and test the affected
workflow before adopting it. These static proposals do not establish functional
dependence, runtime behavior, or isolation. Offline requests can still fail when
required artifacts are missing from the cache.

## Supported configuration

Proposals only enable explicitly present, disabled `HF_HUB_OFFLINE`,
`HF_HUB_DISABLE_TELEMETRY`, and `HF_HUB_DISABLE_UPDATE_CHECK` switches. The
supported disabled literals are `0`, `false`, `no`, and `off`, ignoring case.
The replacement is `1`, preserving supported quotes and whitespace. Missing
switches, enabled values, empty values, and arbitrary values produce no patch.
The switch behavior follows the
[Hugging Face environment-variable reference](https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables).

Dotenv input uses single-line `KEY=value` assignments in `.env`, `.env.*`, or
`*.env` files. Spaces around `=` and simple single or double quotes are
supported. Blank lines, comment lines, and supported assignments to unknown
keys are ignored. Unsupported dotenv syntax skips the whole file because later
physical lines could belong to a multiline value. This includes `export`,
continuations, command substitution, interpolation outside single quotes, and
unquoted shell operators. Duplicate known switch assignments are rejected.

YAML input uses block mappings under `services.<service>.environment` in
`.yaml` or `.yml` files. Environment mappings require unquoted switch keys and
a supported scalar value on the same line. Environment lists support
`- KEY=value` and simple quotes around the entire list entry. Duplicate known
switch names in a list are rejected. Lists containing non-scalar entries are
skipped.

Both formats require the complete changed source line to contain only the
known switch, a supported disabled literal, its assignment syntax, and
whitespace. Inline comments, interpolation, escaped spellings, multiline
scalars, flow layouts, and unsupported structures produce no patch. Only LF
and CRLF line endings are supported; other line separators skip the file.

## Privacy and boundaries

Each `ProposalReport` includes an API version, kind, visited file count,
proposals, coverage, and limitations. A proposal contains a safe relative file
path, original line number, rule ID, and zero-context unified patch. Patches
preserve CRLF and missing-final-newline markers. Each patch changes one line,
so multiple proposals for a file retain their original line numbers.

Patch headers accept only ASCII letters, digits, dots, underscores, hyphens,
and directory separators in local relative paths. Proposals contain no adjacent
lines, comments, arbitrary old values, URLs, or source-content hashes. Errors
omit parser diagnostics and source paths because those can contain secrets.

The root must be an existing directory without symlink components or `..`
components. Reads stay within an `os.Root`. Symlinks and non-regular files in
the visited tree are rejected. Hidden directories, `vendor`, and `node_modules`
are excluded, matching the scanner's directory exclusions; dotenv files remain
eligible. All other visited regular files count toward the input limits,
including unsupported filenames.

Malformed YAML, duplicate mapping keys anywhere in a YAML file, anchors,
aliases, merges, complex or non-string keys, explicit tags, multiple documents,
and nesting deeper than 64 levels are rejected. Validation precedes selecting
the supported Compose layout.

Input is limited to 1 MiB per visited file, 10,000 visited files, and 64 MiB
total. Output is limited to 100 patches and 1 MiB of aggregate patch text.
Cancellation, read failures, unsafe paths, ambiguous syntax, or exceeded limits
return an error and discard every accumulated proposal. Unsupported syntax
described above is skipped; a successful empty report does not establish that
the configuration is ready for offline use.

Keep the source tree stable while generating and reviewing proposals. File
identity, size, and modification checks detect ordinary replacement during a
read, but this API does not create an immutable snapshot. Patches have no
surrounding-content fingerprint; recheck the current source before using them.
