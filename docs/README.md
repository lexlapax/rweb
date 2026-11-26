# rweb documents

## Using rweb

- [User guide](user-guide.md): install; reach it through Tailscale or an SSH tunnel; run it at boot or
  login on Linux and macOS; several machines; using the page; file transfer; upgrade; troubleshooting.
- [Changelog](../CHANGELOG.md): what changed in each version.
- [Licence](../LICENSE): MIT.
- [Third-party notices](../THIRD-PARTY-NOTICES.md): the software rweb contains or serves, with licences.
- [Contributing](../CONTRIBUTING.md): a one-person project; forks are welcome, pull requests are not taken.

## How it works

- [Architecture](architecture.md): components, diagrams, request checks, data and input paths, the
  browser protocol, source layout, pinned dependencies.
- [Security hardening](security-hardening-2026-11-23.md) and the [security review](security-review-2026-11-23.md)
  before it: the threat model, every finding and its fix and test.
- [Release reviews of 0.1.1](release-review-2026-11-25.md): release readiness and a security scan, each
  finding's verdict, fix and test; the [second round](security-review-2026-11-25-round2.md) and the
  [third](security-review-2026-11-25-round3.md): rescans plus internal adversarial reviews, each with its
  plan by mechanism and every fix and test.
- [File transfer](file-transfer.md): design, limits and threat model of the optional file transfer.

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
