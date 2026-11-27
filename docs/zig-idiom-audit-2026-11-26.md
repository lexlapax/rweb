# Zig idiom audit (2026-11-26)

The owner asked: does this project follow the Zig way, compile-time work included, or does the code
base have to be redone? This is the record of the audit that answers it: the verdict, the 24 findings
with their state now, a pass over a 38-item checklist, and the plan for the work that is left.

The findings were made on the code before round five's fixes. Every status and every `file:line` below
was checked again against this tree: `main` at `8155cbb` plus three uncommitted mechanical changes
(`zig fmt` over `src` and `build.zig`, `std.fmt.allocPrint(a, ...)` to `a.print(...)`, `lazyDependency` to
`dependencyLazy`). Zig 0.17.1; std was read from the compiler's own `lib/std`, not from memory.

## 1. Verdict

**No rewrite. A targeted refactor, most of it after 0.1.1.** The structure is what an idiomatic Zig
service of this kind looks like: allocators and `Io` are parameters everywhere, the parsers are pure
and fuzzed, error sets are explicit where they matter, every queue has a limit, the lock order is
written down, and the release is ReleaseSafe. No `unreachable`, unchecked cast or read of undefined
memory was found that bytes from a browser or from Rex can reach.

The honest answer to "compile time optimization" is narrower than the question. The code uses comptime
where it is plain (29 `@embedFile`, header tables joined at compile time, format strings, size asserts,
exhaustive switches) and under-uses it in one place: JSON. It walks `std.json.Value` trees by hand and
glues request bodies from strings where `std.json`'s typed parsing would generate that code, and a Rex
reply is parsed twice and deep-copied once before a field is read. The other real gaps are not about
comptime: nobody chose the release allocator, the hot paths allocate per frame and per keystroke, and
allocation-failure paths are tested in few places.

### What the verdict rests on

- Read in full, non-test code: `rex/ws.zig`, `rex/rex1.zig`, `rex/input.zig`, `rex/control.zig`,
  `rex/wire.zig`, `rex/transfer.zig`, `bridge/hub.zig`, `bridge/server.zig`, `bridge/protocol.zig`,
  `bridge/access.zig`, `bridge/assets.zig`, `bridge/main.zig`, `build.zig`, `build.zig.zon`,
  `tools/dist.sh`, and the parts of std they depend on (`start.zig`, `heap/SafeAllocator.zig`,
  `Io/Threaded.zig`, `Build.zig`, `process.zig`).
- Read in part: `rex/mirror.zig` (not lines 470 to 585), `rex/data.zig`, `rex/api.zig`,
  `bridge/cli.zig`, `bridge/xfer.zig` (the registry, the stat, mount and ACL code; not the path walk
  and the message text, roughly lines 130 to 400 and 1100 to 1850).
- Not read line by line: `bridge/layout.zig`, `rex/fake.zig`, and the bodies of the tests.
- Round five changed `hub.zig`, `main.zig`, `xfer.zig` and `server.zig` after the first reading. The
  changed regions named in the table were read again; the rest of the diff was covered by the
  checklist's searches, not by a second full reading.
- Searches and counts were run over every file. A search is a question, not a proof: it misses
  multi-line forms and aliases.

### What was not done

- Nothing was measured. Every statement about cost (the allocator, per-frame allocation, a watchdog
  per write) is reasoned from this code and std's, not timed.
- The test suite, a long fuzz run, a load test, Valgrind and `readelf` on the Linux archive were not
  run as part of this audit. Items that need one say so.
- Ghostty's own allocation and parsing behaviour was not read.

## 2. Findings F1 to F24

Size: S under 50 lines, M 50 to 300, L more. Status: **fixed in round five**, **fixed now** (the
mechanical changes above), **part fixed**, or **open**.

| id | area | severity | what | status | where now |
|---|---|---|---|---|---|
| F1 | allocators | should-fix | `init.gpa` in a ReleaseSafe build is `std.heap.SafeAllocator` over the page allocator (std `start.zig`); nobody chose it or measured it | **decided in Phase B step 2** (2026-11-26): kept, now stated and checked at compile time | `src/bridge/main.zig:155` |
| F2 | performance | should-fix | `readMessage` allocates and frees a buffer for every message, so once per chunk of terminal output | open (Phase B 3) | `src/rex/ws.zig:517-577` |
| F3 | performance | should-fix | live output is copied per viewer per chunk, and a frame grows by exact-size `realloc` (quadratic, bounded by the 64 KiB frame) | open (Phase B 3) | `src/bridge/hub.zig:229-250` |
| F4 | performance | should-fix | a reply is built with `valueAlloc`, then `push` copies it and the first copy is freed; a redraw (up to 16 MiB) is copied the same way | open (Phase B 3) | `src/bridge/hub.zig:186-188`, `:1238`; 17 `valueAlloc` in `hub.zig` |
| F5 | comptime | should-fix | Rex replies: parsed in `dispatch`, copied, parsed again in `callTimeout`, deep-copied by `cloneValue`, then picked apart by hand; events get a third parse; request bodies are glued from escaped pieces | **fixed in Phase B step 1** (2026-11-26; section 4) | `src/rex/control.zig:490`, `:599`; `src/rex/api.zig:114`, `:583`; `src/rex/rex1.zig:182`; `src/rex/wire.zig:31`; `src/bridge/hub.zig:466`; `src/bridge/main.zig:731`, `:759` |
| F6 | comptime | should-fix | message type matched by a chain of `eql`; `classOf` ended in `else => .free` | **fixed in round five**: `stringToEnum` and an exhaustive switch; both class functions list every tag, and a comptime loop refuses a tag that is under a mirror's lock and free | `src/bridge/protocol.zig:91-92`; `src/bridge/hub.zig:667-692` |
| F7 | errors | should-fix | allocation failures swallowed with a wrong state left behind | **part fixed in round five**: the hub needs no memory to close, restart or drop a terminal (lists linked through `Terminal.link`, a `closed` frame kept from the open, a reserved queue slot). **Open**: a connection whose tracking `append` fails is served untracked, so `stop` cannot shut it | fixed: `src/bridge/hub.zig:266-283`, `:1519-1532`, `:1553-1640`; open: `src/bridge/server.zig:643` |
| F8 | C interop | should-fix | two `peerUid` functions, the server's with hard-coded socket constants | **fixed in round five**: one function, std's constants, the returned length checked | `src/rex/ws.zig:199-220`; called at `src/bridge/server.zig:574`, `:732` |
| F9 | C interop | should-fix | `fdMount` returned an empty answer (which passes) on other systems, and assumed 64-bit words with only a comment | **fixed in round five**: `@compileError` for another OS or word size | `src/bridge/xfer.zig:781`, `:791`, `:801` |
| F10 | C interop | nice-to-have | `umask` re-declared; raw errno numbers | **fixed in round five** | `src/bridge/server.zig:95-96`; `src/bridge/xfer.zig:986-990` |
| F11 | performance | should-fix | every frame written to Rex starts and cancels a watchdog task | open (Phase B 5) | `src/rex/ws.zig:476-481` |
| F12 | design | should-fix | one mutex serialises every Rex call of every viewer, only to guard `Api.last_error` | open (Phase B 5) | `src/bridge/hub.zig:489`; `src/rex/api.zig:73` |
| F13 | concurrency | should-fix | `supervisor_wake` is set and never waited on (the supervisor polls every 200 ms); `openStream` polls the mirror every 5 ms | open (Phase B 5) | set at `src/bridge/hub.zig:404`, `:1343`, `:1540`; polls at `:1450`, `:1167-1169` |
| F14 | one way | nice-to-have | three hand-written constant-time compares; own addresses parsed from text on every request | open | `src/bridge/access.zig:363`, `:221-229`; `src/bridge/server.zig:1336`; `src/bridge/xfer.zig:129` |
| F15 | allocators | nice-to-have | `checkFdExtras` used the page allocator from inside | **fixed in round five**: it takes an allocator | `src/bridge/xfer.zig:1053` |
| F16 | memory | nice-to-have | a browser connection carries 128 KiB of buffers it never uses | open | `src/rex/ws.zig:301-302`, `:440` |
| F17 | safety style | nice-to-have | `term` and `vt` are `undefined` behind a `term_made` flag; `r` and `w` default to `undefined` | open | `src/rex/mirror.zig:111-115`; `src/rex/ws.zig:277-278` |
| F18 | errors | nice-to-have | `anyerror` where an inferred or named set would do (25 functions); Zig error names reach the browser | open | `src/rex/rex1.zig:60`, `:144`, `:155`; `src/bridge/hub.zig:764`, `:820`, `:902`, `:988`; `src/bridge/server.zig:1234` |
| F19 | build | nice-to-have | ETags and gzip bodies are made at run time on first use; lookup is a scan of 28 entries | open | `src/bridge/server.zig:908-926`; `src/bridge/assets.zig:46-54` |
| F20 | build | should-fix | libc not asked for; the Linux release not position independent | **fixed in round five**: `link_libc = true`, `pie` on Linux. The archive itself: see checklist item 34 | `build.zig:27`, `:34`, `:69` |
| F21 | build | nice-to-have | the bridge's module graph is built twice; `optimize: anytype`; a plain `zig build` is Debug | open | `build.zig:21-36` against `:65-80`; `build.zig:21`; `build.zig:48` |
| F22 | style | nice-to-have | `@hasField` on the project's own struct; a function-static buffer; tests before `main`; a long `main`; help and version returned as errors | **part fixed in round five**: the `@hasField` is gone and `rexProblem` takes a buffer (`src/bridge/main.zig:614`). **Open**: tests at `src/bridge/main.zig:26-74` before `main` at `:154`; `main` is 269 lines; `src/bridge/cli.zig:146-150` | as named |
| F23 | performance | nice-to-have | four or five small allocations per keystroke; byte-wise masking; a ping payload copied to the heap; hand-made deques | open (Phase B 3) | `src/rex/input.zig:285-305`, `:273`; `src/rex/ws.zig:504`, `:553`, `:560`; `src/bridge/hub.zig:88`, `:171` |
| F24 | tests | nice-to-have | waits are polls with wall-clock limits; `checkAllAllocationFailures` is not used | open (Phase B 4, 5) | 0 uses; 56 `sleep` calls, about 40 of them in tests |

**Fixed now**, not in the table because the first pass treated them as the repository's choice: the
0.17 names. `@intFromEnum` and `@enumFromInt` are `@backingInt` and `@fromBackingInt`,
`std.fmt.allocPrint` is `Allocator.print` (204 places), `lazyDependency` is `dependencyLazy`, and
`zig fmt --check build.zig src` is clean. Two deprecated calls are left: see checklist item 4.

## 3. The checklist, item by item

The checklist is the research note "What is the Zig way for a production codebase (Zig 0.15 to 0.17)",
38 items. Each item's search was run over `src` and `build.zig` of this tree. Status is **pass**,
**fix needed**, **not applicable**, or **needs a run** where only a run this audit did not do can
answer. Counts are whole-tree, tests included, unless said.

Tally: 20 pass, 16 fix needed, 1 not applicable, 1 needs a run.

| # | item | status | evidence | change, if one is needed |
|---|---|---|---|---|
| 1 | Toolchain pin | pass | `build.zig.zon`: `minimum_zig_version = "0.17.1"`, Ghostty by tag `vt-1.0.1` with its content hash; `tools/release.sh` builds only with a `zig-0.17.1` on PATH. The repository has no CI. | |
| 2 | Format, build, test | fix needed | `zig fmt --check build.zig src` passes. 335 test declarations in 21 files. `tools/release.sh` runs `zig build test` in Debug and then packs a ReleaseSafe build: the tests never run in the mode that ships. The suite was not run for this audit. | Run the test step with `-Doptimize=ReleaseSafe` as well, in `tools/release.sh`. |
| 3 | Dead code analysis | pass | No `refAllDecls`; every file is reached through `test { _ = ...; }` (`src/rex/root.zig:15`, `src/bridge/main.zig:1124`) and each has tests (3 to 52). `fuzz.zig` is its own module. Linux-only branches are compiled on macOS only by `zig build dist`, and their tests run only on Linux. | |
| 4 | Stale APIs | fix needed | None of the listed names is left, except two deprecated `std.fmt.allocPrintSentinel` in tests (`src/bridge/xfer.zig:2020`, `:2359`). `std.fs.path` (10 uses) is current. | `arena.printSentinel(...)` in those two places. |
| 5 | Upgrade hazards | pass | Three `@bitCast`, all between scalar integers of one width: `dev_t` to `u32` or `u64` (`src/bridge/xfer.zig:478-479`) and a descriptor `isize` to `usize` for a raw system call (`:783`). None is on an array, a vector or an `extern` type, so 0.17's logical bit order does not touch them. No `containsAtLeastScalar`. | |
| 6 | Release mode | fix needed | The archives are forced to `.safe` (`build.zig:98`) and Ghostty is given the same mode (`build.zig:22`, `:51`). No `@setRuntimeSafety`. But `standardOptimizeOption(.{})` (`build.zig:48`) makes a plain `zig build` a Debug build, where Ghostty is hundreds of times slower; the README tells builders to pass `-Doptimize=ReleaseSafe`. | `preferred_optimize_mode = .safe`, or say in the build's own help what a plain build is. |
| 7 | Safety overrides and casts | pass | 34 `@ptrCast` (27 recover a callback's context, 6 are socket and ACL calls, 1 turns `[][]u8` into `[]const []const u8`), 29 `@alignCast`, 0 `@constCast`, 0 `@ptrFromInt`, 59 `@intCast`, 6 `@truncate`, 5 wrapping operators (2 sequence counters, 3 test patterns). Every `@intCast` on a value from a browser or Rex follows a range check (`src/rex/ws.zig:545`, `src/rex/wire.zig:52-55`, `:119-120`, `src/rex/control.zig:496-505`, `src/bridge/protocol.zig:110`, `:156`, `src/rex/api.zig:494`). | |
| 8 | `unreachable` and panics | pass | 4 bare `unreachable`: three after a dispatch that already chose the tag (`src/bridge/hub.zig:851`, `:956`, `:985`), one state handled just above (`src/rex/input.zig:385`). 11 `catch unreachable`: 7 in tests, 4 into a buffer sized for the worst case (`src/bridge/server.zig:876`, `src/bridge/xfer.zig:245`, `src/rex/control.zig:434`, `src/rex/rex1.zig:238`). No `@panic`. | |
| 9 | Swallowed errors | fix needed | 84 `catch {}` (about 50 outside tests): socket shutdown, close frames, cleanup deletes and messages into fixed buffers are best effort on a path already ending. Not justified: `src/bridge/server.zig:643` (see F7); `src/bridge/server.zig:153`, where the result of `fcntl(FD_CLOEXEC)` on the loopback listener is thrown away; and the hub's replies, which are dropped without a word when `valueAlloc` fails (`catch return`, 45 in the tree). | Refuse the connection when it cannot be tracked; fail `listenLoopback` when `fcntl` fails; count dropped replies in `Viewer.overflows` and log once. |
| 10 | Error sets | fix needed | Explicit sets at the trust boundaries: `cli.Error`, `xfer.CheckError` and `OpenError`, `protocol.ParseError`, `ws.ParseError`, `api.Error`. But 47 `anyerror` (25 function signatures), 59 public functions with inferred sets, and `@errorName` as the text of a browser error (F18). Out of memory is kept apart from bad input everywhere it was read. | Phase B 1 and F18: named sets on the `rex` entry points; a small error-to-code table for the browser. |
| 11 | Cancelation and causes | fix needed | Loops end on `Canceled` (`src/bridge/server.zig:561`, the sleeps' `catch return`, `src/rex/control.zig` reader, `src/rex/data.zig` reader); `swapCancelProtection` guards a frame being written (`src/rex/ws.zig:477`). No `.?` on a stream's `err`. But the cause behind `ReadFailed` and `WriteFailed` is never read (no use of a reader's or writer's `err`), so the log says "connection ended: ReadFailed" (`src/bridge/server.zig:661`) whatever happened. In `Hub.handle` a `Canceled` becomes an error frame for the browser; the task still ends, because `stop` shuts the socket first. | Log `r.err` / `w.err` where a connection ends. |
| 12 | `errdefer` and `defer` | fix needed | 106 `errdefer`; ownership handed over is said in comments (`Registry.add`, `Input.push`). One leak found: **`Hub.open`** (`src/bridge/hub.zig:524-534`) frees only the struct when it fails, so a failed first `attach_all` or tree read leaves `Api.last_error` allocated, and a failed task start also leaves the tree and its key set. `main` calls it again on every retry while Rex is not ready (`src/bridge/main.zig:593`). A few dozen bytes per failed try, at most every 10 s. | `errdefer` in `Hub.open` that frees what `close` frees (`api.deinit`, the tree, `known`). A test with `checkAllAllocationFailures` (item 30) would have found it. |
| 13 | Allocator flow | fix needed | One source: `init.gpa` (`src/bridge/main.zig:155`), passed down; no `page_allocator`, `c_allocator` or `smp_allocator` anywhere in `src` now. What `init.gpa` is in the shipped mode is known (`SafeAllocator`) but not chosen or measured (F1). | Phase B 2. |
| 14 | Arena and fixed-buffer lifetime | pass | 65 arenas, nearly all per call or per test. The one that lives as long as a connection is reset for each message with `.retain_capacity` (`src/bridge/server.zig:1232`); a message is at most 64 KiB, so what it keeps is bounded, and the parsed message is not used after the reset. The theme and the tree's key set are replaced whole. No fixed-buffer allocators. | |
| 15 | Ownership and stale pointers | pass | 6 `take*`/`peek` calls, all in `src/rex/ws.zig`: a line is used or copied (`key_buf`, `:332`) before the next read, and a header is parsed before `toss`. The download token is copied before the body is read (`src/bridge/server.zig:797-798`). Pointers into lists (`src/bridge/hub.zig:236`, `src/rex/input.zig:261`) are used under the lock before any append. A call's `Pending` lives on the caller's stack and is taken out of the map before it returns (`src/rex/control.zig:435-452`). | |
| 16 | Resource limits | fix needed | Limits exist for connections (64), viewers (32), unanswered connections (16), headers (64), a browser message (64 KiB), a Rex message (1 MiB data, 16 MiB control), a viewer's queue (1 MiB live, 256 replies, 8 MiB), the event ring, the input queue (4096 items, 1 MiB), transfers (16 waiting, 4 running), the snapshot (256 MiB), scrollback (10,000 lines, 32 MiB), a redraw (16 MiB). Without one: the output of `tailscale` (`std.process.run` with the default unlimited `stdout_limit`, `src/bridge/main.zig:723`, `:752`, `:783`), and the set of attached session ids, which only grows (`Hub.attached`). The three `appendRemainingUnlimited` are in tests. | `.stdout_limit` and `.stderr_limit` of 1 MiB on the three runs; drop a session from `attached` when the tree no longer has it. |
| 17 | Concurrency choice | pass | Only `concurrent`, never `async` (about 20 places outside tests). The accept loop enforces its own limits and closes the stream when no task can be had (`src/bridge/server.zig:584-606`); every future is cancelled or awaited; the group is cancelled in `stop`. A connection whose head watchdog cannot start is served without it (`src/bridge/server.zig:647`); eviction of the oldest silent connection still bounds it. | |
| 18 | Shared state | pass | Lock order is documented (`src/bridge/hub.zig:5-13`); 20 mutex and 25 atomic uses, all `Io` primitives. Two mutable globals, both in `main.zig` and written once at startup: `held` (`:99`) and `StopSocket` (`:109`), which the signal handler reads. Output reaches viewers under the mirror's lock by design, through queues that never block. | |
| 19 | Timeouts and backpressure | fix needed | Deadlines exist for a handshake (10 s), a request head (10 s), a silent browser (20 s, measured between whole messages, so a trickled message does not reset it), a frame not read (30 s), a transfer that moves nothing (30 s), a Rex call (30 s, or 5 s for the page's quick ones) and a write to Rex (10 s). Missing: `tailscale` is run with no timeout. A `tailscale ip` that hangs stops the loop that refreshes this node's own addresses (`src/bridge/main.zig:404-408`) without a word, and the bridge goes on with the old list. The behaviour with silent, trickling and non-reading peers was not run here. | `.timeout` of a few seconds on the three `std.process.run` calls; a timed-out refresh counts as failed and is reported as failures already are. |
| 20 | Reader and writer use | pass | The interface is always taken by pointer from a field of a heap or stack value that outlives it (`src/rex/ws.zig:312-313`, `:401-402`; `src/bridge/server.zig:670-672`). Every frame ends in a flush whose error is returned (`src/rex/ws.zig:497`, `:508`). Lines are read with `takeDelimiterInclusive`, which refuses an unterminated last line. A frame is assembled from as many reads as it takes (`readSliceAll`). | |
| 21 | Untrusted input | pass | By reading: lengths are checked before arithmetic and before allocation (`src/rex/ws.zig:54-87`, `src/rex/wire.zig:99-124`), byte order is explicit (`readInt` with `.big` or `.little`), no wire bytes are cast into a struct, masking is enforced both ways (`src/rex/ws.zig:541-542`), `Origin` and the access rules come before anything else (`src/bridge/server.zig:715-770`), names and paths are bounded and cleaned (`src/bridge/protocol.zig`, `xfer.safeName`). The five security review rounds are the deeper record for this item. | |
| 22 | Stream per session | pass | One VT stream per mirror, made once when the snapshot is decoded (`src/rex/mirror.zig:253`) and freed before its terminal (`:154-157`). A test feeds the snapshot and the output one byte at a time (`:673`), and another splits OSC and DCS strings anywhere (`:1477`). | |
| 23 | libghostty limits and effects | pass | Size is checked before the snapshot is decoded, after it, and on every resize (`resizeAllowed`: 4096 a side, 1,048,576 cells; `src/rex/mirror.zig:54-55`, `:232-250`, `:304`). Scrollback is capped at 10,000 lines and 32 MiB or Rex's smaller limits (`:272-279`). Kitty graphics and glyph commands are off and their storage limit is 0 (`:240`, `:284-285`); OSC and DCS strings are held to 64 KiB (`:287-289`). `vtStream` applies state only, so the mirror answers nothing a program asks. | |
| 24 | libghostty lifetime and reentry | pass | Every access to a terminal is under its mirror's lock. Callbacks run under that lock with borrowed bytes; the hub copies them before the call returns (`src/bridge/hub.zig:229-250`, `:382-388`) and never calls back into the mirror (the rule on `deliver`, `src/rex/mirror.zig:417`). The data stream is closed before its mirror is freed, on close and on restart (`src/bridge/hub.zig` `destroyTerminal`, `restartTerminal`). | |
| 25 | C boundary | fix needed | No `@cImport`, no `[*c]`. But the calls are not behind one wrapper: `std.c.` or `extern "c"` appears in `xfer.zig` (27), `server.zig` (17), `main.zig` (9), `ws.zig` (4), `layout.zig` (1). 12 hand-written declarations (11 macOS ACL functions and `getpeereid`) are checked against no header; `DarwinStatfs` has a size and offset assert (`src/bridge/xfer.zig:772-774`), the peer-credentials struct does not (its returned length is checked, `src/rex/ws.zig:215`). Status codes are checked except `fcntl` (item 9). A leak run under Valgrind, for Ghostty's C++ side, was not done. | One `sys.zig` that owns every raw call and turns status codes into error sets; a comptime size assert beside each hand-written struct; a Valgrind run on Linux. |
| 26 | Comptime value and cost | pass | 16 `comptime`, 17 `anytype`, 2 `inline for` (both in tests), 4 `@typeInfo`, 0 raised quotas, 21 `std.meta` uses. Generics have real uses (`Owned(T)`); `anytype` is used to pass a test double (`chooseTailscale`, the ACL rules, the splitter's sink). Nothing generates code that is hard to follow. `zig build --time-report` was not run. | |
| 27 | Tables and embeds | pass | Message types and terminal actions go through `stringToEnum` (`src/bridge/protocol.zig:91`, `:114`). Header names are compared without case (14 `eqlIgnoreCase`). 29 embedded files, all public page assets. The command line is a chain of about 40 `eql`, which reads well enough as it is; the asset table is scanned (F19). | |
| 28 | Data layout | pass | No `packed`. Two `extern struct`, both for a system call. Nothing here is numerous enough for `MultiArrayList` to matter: tens of terminals and viewers. 21 `create` calls, one per long-lived object. | |
| 29 | `undefined` and output bytes | pass | 309 `undefined`, nearly all buffers. What is written out is a slice of what was filled (`hdr[0..n]` at `src/rex/ws.zig:493`, `w.buffered()`), and whole arrays are sent only after every byte is set (`src/rex/transfer.zig:54-57`, `src/rex/data.zig:115-117`, the 25-byte resume record). | |
| 30 | Leak and OOM tests | fix needed | `testing.allocator` 470 times; no test uses the page allocator. `FailingAllocator` in 5 tests (`src/rex/control.zig:940`, `src/rex/mirror.zig:986`, `:1408`, `:1481`, and the hub's counting allocator). **`checkAllAllocationFailures`: 0 uses.** No owning type has each of its allocations failed in turn; item 12's leak is what that leaves. | Phase B 4. |
| 31 | Fuzzing and negative tests | fix needed | 10 fuzz targets in `src/fuzz.zig` (frame header, handshake, welcome, message body, the splitter against a reference with arbitrary cuts, snapshot framing in pieces, message reassembly, the browser protocol, the access decision, origin matching); 3 carry a corpus; 247 `expectError`. Not fuzzed: the mirror (the fuzz build leaves Ghostty out), `cleanPaste`, `escCut`, `parseMountInfoLine`, `checkPosixAcl`. A long fuzz run was not done here. | Fuzz targets for the four pure functions named; a mirror target that runs as an ordinary test if it cannot be instrumented. |
| 32 | Test control | fix needed | `-Dtest-filter` exists (`build.zig:60`); tests use `std.testing.io` (501 uses); live tests skip without `REX_SOCKET` (25 `SkipZigTest`). But about 40 waits in tests are sleeps and polls with wall-clock limits, no `--test-timeout` is set anywhere, and there is no CI. | Phase B 5 (events to wait on); `--test-timeout` in `tools/release.sh`. |
| 33 | Build hygiene | pass | No `findProgram`. The two script steps run at make time and are marked `has_side_effects` (`build.zig:16`, `:95`); the commit is deliberately not read while configuring. Two options (`test-filter`, `commit`). `zig-pkg/` is ignored. `dependencyLazy` is used for a dependency the manifest does not mark lazy, where `b.dependency` would say the same with less (`build.zig:22`, `:51`). | |
| 34 | Release artifact | pass | The Linux archive's binary, built from this tree and read with `readelf -lW` and `readelf -d` on Linux: type `DYN` (position-independent executable), no `INTERP`, no `NEEDED` entries, `GNU_STACK` not executable, `GNU_RELRO` present, `BIND_NOW`; it runs (`--version`). Not done: a load run of that artifact, LTO or CPU-baseline comparison. |
| 35 | `single_threaded` | not applicable | Not set anywhere; the server needs real concurrency. | |
| 36 | Diagnostics and shutdown | fix needed | 47 scoped `std.log` calls; refusals are logged by reason, never with header values, tokens or client text (`knownPath`, `src/bridge/server.zig:1370`). `std.debug.print` (15) is `say`, the operator's startup messages, on purpose. Missing: error return traces are off in ReleaseSafe and `error_tracing` is not set; the release is stripped and `tools/release.sh` keeps no unstripped copy, so a panic's addresses cannot be mapped to source. SIGTERM and SIGINT end the process with `_exit` after removing its socket (`src/bridge/main.zig:128-131`): an upload in progress leaves its partial file behind, because the `defer` that removes it never runs (`src/bridge/server.zig:1113-1116`). | Keep the unstripped binaries beside each release; measure `error_tracing` in ReleaseSafe; write uploads under a temporary name that startup clears, or say in the user guide that a stop mid-upload leaves a partial file. |
| 37 | Naming and docs | pass | Official casing throughout; 1254 doc-comment lines that give ownership, lifetimes and which lock guards what. Small things: the type `Data` (`src/rex/data.zig:48`) is a filler name, and the test double `fake` is exported from the library's root (`src/rex/root.zig:6`). | |
| 38 | Optional TigerStyle pass | fix needed (house style) | 11 functions are over 70 lines: `main` 269, `Server.serve` 203, `cli.parseEnv` 168, `xfer.explainWith` 163, `Control.callTimeout` 91, `serveUpload` 87, `Splitter.feed` 84, `Hub.handle` 74, `redrawInto` 73, `refreshTree` 72, `viewerSession` 71. One recursion, bounded at depth 64 (`cloneValue`, `src/rex/api.zig:583`; it goes with Phase B 1). Three assertions in the whole tree (`src/bridge/main.zig:96`, `src/bridge/xfer.zig:180`, `:773`). No unbounded loop driven by a peer was found. | Phase B 6. |

### Correctness and security items from this pass

Fixed in the same commit as this document, each small: `tailscale` now runs with a 10 s deadline and a
1 MiB cap on its output (items 16 and 19); a failed `Hub.open` frees what it made; a connection that
cannot be tracked is closed, not served (the rest of F7); a failed close-on-exec on the loopback listener
fails the listener; the two `allocPrintSentinel` calls use `Allocator.printSentinel`; and
`tools/release.sh` runs the tests in `ReleaseSafe`, the mode it packs (item 2). A stop signal in the
middle of an upload no longer leaves a file that looks whole: uploads are written to a part file, named
when complete, and leftover part files are removed at the next start (a later commit).
Two of these were not enough as first made, and were redone in round 6
([security-review-2026-11-26-round6.md](security-review-2026-11-26-round6.md)): the `tailscale` deadline
was `std.process.run`'s, which restarts with every read and does not cover the exit (now
`src/bridge/proc.zig`, one deadline for all of it); and the removal of leftover part files could take
an upload in progress in another rweb (now a folder of rweb's own and a lock on each part file).
The text below is the finding as made, before those fixes.

None is a way in, a crash from peer input, or unbounded memory. In order of weight:

1. **`tailscale` is run with no timeout and no output limit** (items 16, 19; `src/bridge/main.zig:723`,
   `:752`, `:783`). A hung `tailscale ip` freezes the own-address refresh silently; the rule that
   refuses requests from this node's own addresses then runs on the last list it had.
2. **`Hub.open` leaks on failure** (item 12; `src/bridge/hub.zig:524-534`), once per failed try while
   Rex is not ready.
3. **A connection that cannot be tracked is still served** (F7, item 9; `src/bridge/server.zig:643`),
   so `stop` cannot shut it.
4. **`fcntl(FD_CLOEXEC)` on the loopback listener is not checked** (item 9;
   `src/bridge/server.zig:153`). If it ever failed, the `tailscale` child would inherit the listener.
5. **A stop signal during an upload leaves the partial file** (item 36).

## 4. Phase B: after 0.1.1, in this order

Each step names what to measure before and after, so the change is judged on numbers and not on taste.
A fixed workload is needed first and is part of step 2: one terminal producing a known amount of
output (for example 100 MiB of `yes` and a full-screen redraw loop), one and three viewers, and a
script that types 1,000 keys; all against the fake server for repeatability and once against a real
Rex, in ReleaseSafe.

1. **Typed JSON in the Rex client (F5, part of F18).** Result structs parsed with
   `std.json.parseFromValueLeaky(T, arena, payload, .{ .ignore_unknown_fields = true })`; requests
   written with `std.json.Stringify` from anonymous structs; the envelope parsed once and handed to
   the waiting call; `cloneValue` and its recursion removed. Keep the field-by-field checks of
   `protocol.zig`: that input is hostile, and its limits are the point.
   Measure: lines in `rex/api.zig`, `rex/control.zig`, `rex/rex1.zig`; allocations and bytes per
   `session.list` and per `terminal.write` (a counting allocator in a test); the time of a tree
   refresh with 50 sessions. The fuzz targets for the welcome and the message body must still pass,
   and each typed struct gets a test with a missing, a wrong-typed and an extra field.

   **Done 2026-11-26.** What changed:
   - `control.zig`: the reader parses a reply once and hands the parsed tree to the waiting call
     (before: it copied the text and the call parsed it again). A request is written in one pass by
     `std.json.Stringify` (`callValue`), its payload a struct or raw JSON text.
   - `api.zig`: every answer is read into a type in `api.Payload` by one `decode` (`parseFromValueLeaky`,
     unknown fields ignored, any mismatch `BadShape`); `cloneValue` and the hand-written field picking
     are gone; requests are anonymous structs, not glued strings. std parses a JSON tree with an
     explicit stack and the typed read goes only as deep as the type, so the depth guard went too.
   - Not done here: events are still kept as raw text and read by the hub (a third parse, F5's last part);
     `rex1.zig` is untouched (it parses the data stream's own messages, not Rex's control JSON).

   Measured with `src/rex/measure.zig` (`RWEB_MEASURE=1 zig build test -Doptimize=ReleaseSafe`), the
   client against the fake with 50 sessions, per call. Allocations and bytes are the same on macOS
   (Apple silicon) and Linux (x86-64, musl); times are macOS's, three runs each (the Linux host was too
   busy for stable times).

   | call | allocations before → after | bytes before → after | time before → after |
   |---|---|---|---|
   | `session.list`, 50 sessions | 30 → 13 | 171,348 → 67,504 | 100–118 µs → 79–81 µs |
   | `session.list_blocks` | 27 → 10 | 14,351 → 6,451 | 22–26 µs → 22 µs |
   | `block.event` (a paste) | 31 → 8 | 9,511 → 4,008 | 22–25 µs → 23–24 µs |
   | `terminal.resize` | 27 → 8 | 8,429 → 4,008 | 18–22 µs → 20–21 µs |
   | tree refresh (list and 50 × blocks) | 1,380 → 513 | 889,111 → 390,180 | 974–1,083 µs → 880–914 µs |

   A call's time is mostly the round trip over the socket, so small calls did not get faster; the
   memory work did drop by 57 to 74 % in allocations and 53 to 61 % in bytes. `api.zig` went from 927 to
   about 800 lines with the new tests; `control.zig` grew by 30 (the request writer).

   Found on the way:
   - An empty anonymous literal `.{}` is a tuple, and `std.json` writes it as `[]`. The first version
     sent `"payload":[]` and `"args":[]`; Rex refuses those (`cannot unmarshal array`), the fake took
     them. Now `no_args` (an empty struct) is sent, a test pins both forms, and **the fake refuses a
     payload or `args` that is not an object**, as Rex does. Found only by the live tests against a real
     Rex: the fake had been more lenient than Rex.
   - The fake answered a missing folder with `"entries":""` (a `[]u8` is written as a string); fixed.
   - std.json reads a list of small numbers into a text field as bytes, and a numeric string into an
     integer field. Neither matters for Rex's answers; the tests' wrong-type cases avoid them.

   Checks: macOS `zig build test` 334 passed, 11 skipped; with the live Rex (0.1.0-preview.21, revision
   18) in ReleaseSafe 342 passed, 3 skipped; Linux with the live Rex (preview.22, revision 19) in
   ReleaseSafe 411 passed, 4 skipped; web tests 44/44; `zig fmt --check` clean; `rex ls` unchanged on
   both. Each answer type has a test with an extra, a missing and a wrong-typed field.

2. **The release allocator, decided from measurements (F1).** Candidates: `SafeAllocator` as now
   (use-after-free and double-free checks in the shipped binary), `std.heap.smp_allocator` in
   release with the safe one kept for Debug and tests, or `c_allocator` on musl.
   Measure, for each, on the workload above: CPU time of the bridge, peak and settled RSS after an
   hour, system calls per MiB of output (`strace -c` on Linux), keystroke round trip at the median
   and the 99th percentile. Write the choice and the numbers in `docs/`, and say what safety is
   given up if the choice is not the safe allocator.

   **Done 2026-11-26: the safe allocator stays**, now a stated decision (a comment where `main` takes
   it, and a compile-time error for a build mode that would get another allocator).

   The fixed workload is `src/bridge/bench.zig` (`RWEB_BENCH=1 RWEB_BENCH_ALLOC=safe|smp|c zig build test
   -Doptimize=ReleaseSafe -Dtest-filter=bench:`): the real Rex client, hub and server on the chosen
   allocator, in one process with the fake Rex and three simulated browsers (those on `smp_allocator` in
   every run). It sends 32 MiB of terminal output to one viewer and then to three, then types 1,000
   words of a few characters each (one every 10 ms at most, under the bridge's 200-messages-a-second
   flood limit), timing each until its echo arrives. Three runs per allocator on each machine.

   | | safe (`SafeAllocator`) | `smp_allocator` | C allocator |
   |---|---|---|---|
   | macOS: total CPU | 1,219–1,294 ms | 1,151–1,186 ms | 1,137–1,173 ms |
   | macOS: 32 MiB to 3 viewers | 129–134 ms wall | 127–131 ms | 121–125 ms |
   | macOS: key round trip, median / p99 | 3.09–3.12 / 3.47–3.68 ms | 3.08–3.14 / 3.48–3.62 ms | 3.07–3.16 / 3.43–3.56 ms |
   | macOS: page faults | ~48,700 | ~46,300 | ~31,000 |
   | Linux (musl): total CPU | 1,285–1,361 ms | 1,219–1,242 ms | 1,188–1,199 ms |
   | Linux: CPU while typing | 810–845 ms | 714–720 ms | 659–704 ms |
   | Linux: key round trip, median / p99 | 1.67–1.70 / 2.79–2.85 ms | 1.70–1.73 / 2.78–2.80 ms | 1.66–1.74 / 2.76–2.81 ms |
   | Linux: page faults | ~121,000 | ~114,500 | ~117,900 |
   | Linux: resident after 3 s idle | 82–86 MB | 79–83 MB | 81–84 MB |

   The safe allocator costs 5 to 12 % more CPU in all (15 to 25 % while typing), at the same latency
   and memory. What another allocator would give up: use-after-free and double-free detection in the
   shipped binary (a crash instead of corrupted memory). For a bridge that holds the owner's full Rex
   access, kept.

   Limits of the measurement: the process's memory is mostly the fake Rex holding the output, so peak
   memory does not tell the allocators apart; system calls were not counted (`strace` is not installed
   on the Linux host, and installing it goes through the owner's setup repository); "after an hour" was
   3 seconds. The round trip of a key (about 3 ms on macOS, 1.7 ms on Linux) is the same with every
   allocator: it is waits elsewhere, for step 5 to look at.

3. **Allocations per frame and per keystroke (F2, F3, F4, F16, F23).** A read buffer kept per
   connection; live frames with their capacity taken once, or a ring per viewer; `pushOwned` for
   replies and for the redraw; the ids escaped once per input queue and one buffer per request; no
   heap copy for a ping.
   Measure: allocations per output chunk and per keystroke, before and after, with a counting
   allocator in a test (the target is 0 on the output path once warm, and 1 per keystroke); then the
   step 2 workload again.

4. **`checkAllAllocationFailures` for each owning type and request path (F24, item 30).** `Hub.open`
   and `close`, `Control.open`, `Data.openTerminal`, `Input.open`, `Mirror` from snapshot to live,
   `Registry.add` and `take`, `Server.startBound`, `protocol.parse`, `cleanPaste`, `shellQuote`,
   `wire.parseWelcome`, `rex1.parseBody`, each `Api` call against the fake, and a hub `handle` for
   every message type. Types whose tasks allocate on other threads need the hub's counting allocator
   instead (see `src/bridge/hub.zig:2459`).
   Measure: the number of owning types and message types covered, out of the list above; leaks found
   (item 12's is the first).

5. **Events instead of polling; one write-deadline watcher per connection; the mutex around Rex
   calls (F13, F11, F12).** The supervisor waits on one event that everything now sets; the mirror
   signals "live or failed"; a connection has one task that watches a deadline the writer sets,
   instead of a task per frame; `Api` returns the error text through a parameter, as `xfer.Problem`
   does, and `api_mu` goes.
   Measure: wake-ups per second of an idle bridge (now at least 5 from the supervisor alone); time
   from a block closing in Rex to the page's `closed` frame; time to open a terminal; task starts
   per keystroke (now 1, target 0); the time a `fit` waits while another viewer's directory listing
   is slow (now up to 5 s, target none). The tests that sleep should fall with this: count them
   before and after (about 40 now).

6. **Assertions on internal invariants (item 38).** `std.debug.assert` where a broken invariant
   would otherwise become a wrong answer: reference counts never below zero, a viewer's byte counts
   equal to the sum of its queued frames, a terminal on at most one intrusive list, the lock a
   `...Locked` function requires, the ring's length within its capacity, a frame's kind matching its
   binary flag. Never on anything a peer sends: that stays an error.
   Measure: the count (3 now); a fuzz and test run in ReleaseSafe with them in, to see that none
   fires; the step 2 workload once more, since an assert's argument is evaluated in every mode.

7. **What the checklist adds, small and independent of the above.**
   - The five correctness items of section 3, if any is still open then.
   - Tests in ReleaseSafe and `--test-timeout` in `tools/release.sh` (items 2, 32).
   - Unstripped binaries kept with each release, and `error_tracing` measured (item 36).
   - One `sys.zig` for every raw system and libc call, with size asserts (item 25); a Valgrind run on
     Linux.
   - Fuzz targets for `cleanPaste`, `escCut`, `parseMountInfoLine`, `checkPosixAcl`, and the mirror
     (item 31).
   - The cause behind `ReadFailed` and `WriteFailed` in the log (item 11).
   - `preferred_optimize_mode`, one function that builds the bridge's modules, `b.dependency`
     (items 6, 33, F21).
   - The rest of F14, F17, F18, F19 and F22 as the files are next touched.
