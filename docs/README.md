# rweb documents

## Using rweb

- [User guide](user-guide.md): install; reach it through Tailscale or an SSH tunnel; run it at boot or
  login on Linux and macOS; several machines; using the page; file transfer; upgrade, stop or remove;
  troubleshooting; every option.
- [Changelog](../CHANGELOG.md): what changed in each version.
- [Licence](../LICENSE): MIT.
- [Third-party notices](../THIRD-PARTY-NOTICES.md): the software rweb contains or serves, with licences.
- [Contributing](../CONTRIBUTING.md): a one-person project; forks are welcome, pull requests are not taken.
- [Logo](../assets/logo/README.md): the logo's files, colours, sizes and spacing, and how its images are built.

## How it works

- [Architecture](architecture.md): components, diagrams, request checks, data and input paths, the
  browser protocol, source layout, pinned dependencies.
- [File transfer](file-transfer.md): design, limits and threat model of the optional file transfer.

## How it was reviewed

Before the first release: a security review of the design, then five rounds on the release candidate,
each with an external static security scan, a release-readiness review and an internal adversarial
review in several parts. Every finding was checked against the code, and every fix has a test. Before
each release the candidate is run live on macOS and Linux and tested from the simulators and a phone;
the round's document records those runs.

- [Security review](security-review-2026-11-23.md) and [security hardening](security-hardening-2026-11-23.md)
  (before Phase 4): the threat model, every finding and its fix and test.
- [Round 1](release-review-2026-11-25.md): release readiness and a security scan.
- [Round 2](security-review-2026-11-25-round2.md): a rescan and the first internal adversarial review,
  fixed by mechanism.
- [Round 3](security-review-2026-11-25-round3.md): readiness, rescan and internal review.
- [Round 4](security-review-2026-11-25-round4.md): readiness, rescan, internal review, and the live test
  on macOS and Linux from Android and iOS browsers and a phone.
- [Round 5](security-review-2026-11-26-round5.md): readiness, rescan and an internal review by variant
  (endpoints, lookups, documented procedures); the command line redesigned around `rweb tailscale` and
  `rweb ssh`; a second pass over that new code and a Zig idiom audit.
- [Zig idiom audit](zig-idiom-audit-2026-11-26.md): the code against Zig's own practice, a 38-item
  checklist, what was changed and what is left for after 0.1.1.

## Why it is built this way

- [Plan](PLAN.md): goal, decisions, constraints and phases.
- [Design research](design-research.md): Rex's snapshot format, libghostty-vt, browser terminals,
  Tailscale Serve identity.
- [Rex web research](rex-web-research.md): Rex's protocol, streams and API revisions.

## Test and phase records

What was built in each phase, how it was tested, and what was found: [Phase 0](phase0-result.md) (the
proof that a browser can show a live Rex terminal), [Phase 1](phase1-result.md) (Rex client library),
[Phase 2](phase2-result.md) (the bridge), [Phase 3](phase3-result.md) (the page),
[Phase 4](phase4-result.md) (security review and first deployment), [Phase 5](phase5-result.md) (release
builds). Feedback from daily use: [feedback.md](feedback.md).
