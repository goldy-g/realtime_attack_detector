"""2.2 Attack catalogue: every labelled attack, its alert point and what makes it alertable.

For each of the 27 attacks (24 in the training days, 3 in the eval waves) it
records the alert-point event (type, process, parent, command line, network
end), the process ancestry behind it, the lead-up and steps from the label
write-up, and how many malicious events the attack has.

Writes research/out/attack_catalogue.json and attack_catalogue.md.
"""

from __future__ import annotations

import os

from common import (EVAL, ID, answers, base, day_events, day_labels, iter_events, kind, machines,
                    props, save_json, save_text, split_of, waves)


def describe(ev: dict) -> dict:
    p = props(ev)
    out = {"id": ev["id"], "ts": ev["timestamp"], "kind": kind(ev), "actor_image": base(p.get("image_path")),
           "principal": ev.get("principal")}
    if ev["object"] == "PROCESS":
        out.update(image=base(p.get("image_path")), parent=base(p.get("parent_image_path")),
                   user=p.get("user"), command_line=p.get("command_line"))
    elif ev["object"] == "FLOW":
        out.update(dest="{}:{}".format(p.get("dest_ip"), p.get("dest_port")), direction=p.get("direction"),
                   src="{}:{}".format(p.get("src_ip"), p.get("src_port")))
    elif ev["object"] == "USER_SESSION":
        out.update(user=p.get("user"), src=p.get("src_ip"))
    return out


def ancestry(actor: str, creates: dict, depth: int = 4) -> list[dict]:
    """The acting process and its ancestors, nearest first, from PROCESS CREATE events."""
    chain = []
    while actor in creates and len(chain) < depth:
        ev = creates[actor]
        p = props(ev)
        chain.append({"image": base(p.get("image_path")), "command_line": (p.get("command_line") or "")[:300],
                      "user": p.get("user"), "ts": ev["timestamp"]})
        actor = ev["actorID"]
    return chain


def scan(paths: list[str], wanted: set[str]) -> tuple[dict, dict]:
    """One pass: the wanted events by id, and every PROCESS CREATE keyed by the new process."""
    found, creates = {}, {}
    for path in paths:
        for ev in iter_events(path):
            if ev["object"] == "PROCESS" and ev["action"] == "CREATE":
                creates[ev["objectID"]] = ev
            if ev["id"] in wanted:
                found[ev["id"]] = ev
    return found, creates


def entry(source: str, machine: str, split: str, attack: dict, n_mal: int, n_ctx: int,
          found: dict, creates: dict) -> dict:
    ev = found.get(attack["first_alertable_event_id"])
    point = describe(ev) if ev else None
    return {
        "source": source, "machine": machine, "split": split,
        "attack_id": attack["attack_id"], "name": attack["name"],
        "alert_from": attack["alert_from"], "why_alert_from": attack.get("why_alert_from"),
        "alert_point": point,
        "ancestry": ancestry(ev["actorID"], creates) if ev else [],
        "lead_up": [{"name": a["name"], "n_events": a["n_events"], "ts": a["ts"]} for a in attack.get("lead_up") or []],
        "steps": [{"step": s["step"], "name": s["name"], "n_events": s["n_events"], "ts": s["ts"]}
                  for s in attack.get("steps") or []],
        "n_malicious": n_mal, "n_context": n_ctx,
    }


def train_day(machine: str) -> list[dict]:
    labels = day_labels(machine)
    attacks = labels.get("attacks") or []
    wanted = {a["first_alertable_event_id"] for a in attacks}
    found, creates = scan([day_events(machine)], wanted)
    ea = labels.get("event_attack") or {}
    mal, ctx = set(labels["malicious_event_ids"]), set(labels.get("context_event_ids") or [])
    return [entry("train", machine, split_of(machine), a,
                  sum(1 for i in mal if ea.get(i) == a["attack_id"]),
                  sum(1 for i in ctx if ea.get(i) == a["attack_id"]), found, creates) for a in attacks]


def eval_wave(wave: dict) -> list[dict]:
    answer = answers(EVAL)[wave["wave_id"]]
    attacks = answer.get("attacks") or []
    wanted = {a["first_alertable_event_id"] for a in attacks}
    paths = [os.path.join(EVAL, wave["wave_id"], p + ".stream") for p in ("warmup", "live")]
    found, creates = scan(paths, wanted)
    ea = answer.get("event_attack") or {}
    return [entry("eval " + wave["wave_id"], wave["machine"], "eval", a,
                  sum(1 for i in answer["malicious_event_ids"] if ea.get(i) == a["attack_id"]),
                  sum(1 for i in answer.get("context_event_ids") or [] if ea.get(i) == a["attack_id"]),
                  found, creates) for a in attacks]


def short(cmd: str | None, n: int = 110) -> str:
    cmd = (cmd or "").replace("|", "/").replace("\n", " ")
    return cmd if len(cmd) <= n else cmd[:n] + "…"


def main() -> None:
    from common import pmap
    attacked = [m["machine"] for m in machines() if m["attacked"]]
    rows = [r for day in pmap(train_day, attacked) for r in day]
    rows += [r for w in waves(EVAL) for r in eval_wave(w)]
    save_json("attack_catalogue.json", rows)

    lines = ["# Attack catalogue (2.2)", "",
             "| Attack | Where | Alert point | Process ← parent | Command / destination | Malicious · context |",
             "|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (r["name"], r["machine"])):
        p = r["alert_point"] or {}
        proc = "{} ← {}".format(p.get("image") or p.get("actor_image"), p.get("parent") or "")
        what = p.get("dest") or short(p.get("command_line"))
        lines.append("| {} `{}` | {} {} | {} {} | {} | {} | {} · {} |".format(
            r["name"][:70], r["attack_id"], r["machine"], r["split"], p.get("kind"), p.get("ts", "")[11:23],
            proc, what, r["n_malicious"], r["n_context"]))
    save_text("attack_catalogue.md", "\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
