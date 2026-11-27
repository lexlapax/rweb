# Packages

Made from each signed release, never built separately: they install the release archives, checked by the
SHA-256 in the release's signed `SHA256SUMS`.

| Channel | Template | Published to |
|---|---|---|
| Homebrew (macOS ARM64, Linux x86-64) | `homebrew/rweb.rb.in` | the tap repository `lexlapax/homebrew-rweb`, `Formula/rweb.rb` |
| AUR (Arch Linux) | `aur/PKGBUILD.in` | the AUR package `rweb-bin` (`ssh://aur@aur.archlinux.org/rweb-bin.git`) |

At a release, after `tools/release.sh` and the GitHub Release:

1. `tools/packaging.sh VERSION` checks the signature on `zig-out/release/VERSION/SHA256SUMS` and writes
   `zig-out/release/VERSION/packaging/homebrew/rweb.rb` and `.../aur/PKGBUILD`.
2. Homebrew: copy `rweb.rb` to the tap's `Formula/rweb.rb`, then `brew style` and `brew audit --strict` on
   it from the tap, and commit and push the tap.
3. AUR: on an Arch machine, in a clone of the `rweb-bin` AUR repository, copy `PKGBUILD`, run `makepkg -f`
   (builds without installing) and `makepkg --printsrcinfo > .SRCINFO`, then commit and push.

Checked 2026-11-27 with a trial archive and the 0.2.0 release: `brew style` and `brew audit --strict` pass
(in a temporary tap, trusted and removed again), `brew fetch` downloads the macOS archive and its SHA-256
matches; `makepkg` builds `rweb-bin` on Arch with the binary, the systemd user unit (pointing at
`/usr/bin/rweb`), the docs and the licences. Users of the tap must `brew trust lexlapax/rweb`: Homebrew
loads a third-party tap's formulae only once trusted.
