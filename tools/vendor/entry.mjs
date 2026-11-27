// The wterm bundle's entry (src/bridge/web/vendor/wterm.js): wterm's DOM terminal and its Ghostty
// core, put where wterm-shim.js finds them. Built by tools/vendor/rebuild.sh with esbuild.
import { WTerm } from "@wterm/dom";
import { GhosttyCore } from "@wterm/ghostty";
globalThis.RwebWterm = { WTerm, GhosttyCore };
