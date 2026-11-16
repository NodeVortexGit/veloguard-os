// VeloGuard's guard for OpenClaw (native plugin, typed before_tool_call hook).
// OpenClaw runs no hooks from Claude/Agent-Plugins bundles, so the portable
// "veloguard" plugin brings the guard's MCP tools and skill and this one the
// check: `veloguard check-command` judges every shell command and file edit.
//   deny / warn → a desktop Approve/Deny pop-up (`veloguard approve`): approved
//                 runs, denied or unanswered is blocked — the person decides
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

function describe(event) {
  const p = event.params ?? {};
  const t = String(event.toolName ?? "");
  if (SHELL.has(t.toLowerCase())) return String(p.command ?? p.cmd ?? "");
  return `${t} ${String(p.path ?? p.file_path ?? p.filePath ?? "")}`.trim();
}

function askPerson(event, v) {
  const r = spawnSync("veloguard", ["approve", "--agent", process.env.VELOGUARD_AGENT || "OpenClaw",
                                    "--class", v.class ?? "", "--reason", v.reason ?? "", "--", describe(event)], {
    encoding: "utf8", timeout: 100000,
    env: { PATH: "/usr/local/bin:/usr/bin", HOME: process.env.HOME ?? "",
           XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR ?? "", WAYLAND_DISPLAY: process.env.WAYLAND_DISPLAY ?? "",
           DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS ?? "" },
  });
  try {
    const a = JSON.parse(r.stdout || "{}");
    return { approved: a.approved === true, how: a.how ?? "no answer" };
  } catch {
    return { approved: false, how: "couldn't ask" };
  }
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
      // Anything restricted goes to the person as a desktop Approve/Deny pop-up —
      // OpenClaw's own approval may not reach them (e.g. chatting from the Kimi app).
      const a = askPerson(event, v);
      if (a.approved) return undefined;
      return { block: true, blockReason: `VeloGuard asked the person and they didn't approve it (${a.how}): this ${event.toolName} call ${v.reason}. Take that as the answer — don't retry it or look for another way.` };
    });
  },
};
