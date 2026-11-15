// VeloGuard's guard for OpenClaw (native plugin, typed before_tool_call hook).
// OpenClaw runs no hooks from Claude/Agent-Plugins bundles, so the portable
// "veloguard" plugin brings the guard's MCP tools and skill and this one the
// check: `veloguard check-command` judges every shell command and file edit.
//   deny  → blocked with the reason (switching off / rewriting the guard)
//   warn  → OpenClaw asks YOU (requireApproval), never decided by the agent
//   error → blocked: no check, no command.
import { spawnSync } from "node:child_process";

const SHELL = new Set(["exec", "bash", "shell", "process"]);
const PATCH = new Set(["apply_patch"]);
const WRITE = new Set(["write", "edit", "write_file", "edit_file", "multiedit"]);
const PATCH_FILE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm;

function judge(args, text) {
  const r = spawnSync("veloguard", ["check-command", "--json", ...args], {
    input: text ?? "", encoding: "utf8", timeout: 15000,
    env: { PATH: "/usr/local/bin:/usr/bin", HOME: process.env.HOME ?? "" },
  });
  const v = JSON.parse(r.stdout || "{}");
  if (!["allow", "warn", "deny"].includes(v.verdict)) throw new Error("no verdict");
  return v;
}

function worst(a, b) {
  const rank = { allow: 0, warn: 1, deny: 2 };
  return rank[b.verdict] > rank[a.verdict] ? b : a;
}

function check(event) {
  const tool = String(event.toolName ?? "").toLowerCase();
  const p = event.params ?? {};
  if (SHELL.has(tool)) return judge([], String(p.command ?? p.cmd ?? ""));
  if (PATCH.has(tool)) {
    const patch = String(p.input ?? p.patch ?? "");
    const paths = [...patch.matchAll(PATCH_FILE)].map(m => (m[1] ?? m[2]).trim());
    for (const d of event.derivedPaths ?? []) paths.push(String(d));
    return (paths.length ? paths : [""]).map(f => judge(["--write", f], patch)).reduce(worst);
  }
  if (WRITE.has(tool)) {
    const path = String(p.path ?? p.file_path ?? p.filePath ?? "");
    return judge(["--write", path], String(p.content ?? p.new_string ?? p.newText ?? ""));
  }
  return null;
}

export default {
  id: "veloguard-guard",
  name: "VeloGuard guard",
  register(api) {
    api.on("before_tool_call", (event) => {
      let v;
      try {
        v = check(event);
      } catch (e) {
        return { block: true, blockReason: `VeloGuard couldn't check this call (${e.message}), so it doesn't run.` };
      }
      if (!v || v.verdict === "allow") return undefined;
      if (v.verdict === "deny") {
        return { block: true, blockReason: `VeloGuard refused this: it ${v.reason}. An AI agent never switches off the machine's own protection — tell the person what you wanted to do; they can do it themselves.` };
      }
      return { requireApproval: {
        title: "VeloGuard: check this first",
        description: `This ${event.toolName} call ${v.reason}. Allow it only if you asked for exactly this.`,
        severity: "warning", timeoutMs: 120000, allowedDecisions: ["allow-once", "deny"],
      } };
    });
  },
};
