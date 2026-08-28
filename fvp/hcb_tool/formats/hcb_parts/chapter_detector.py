from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


class ChapterDetectorMixin:
    """Chapter detector based on disassembled function/opcode evidence only.

    There are two supported structural patterns:

    1. body_title_call
       A VM function begins or continues with a title expression, e.g.
           pushint <id> / pushint; neg / ...
           pushstring <visible title>
           call <stable title renderer>
       The call target appears in many body functions and is not a dense menu run.

    2. route_table_call
       A menu/table function registers chapter/route entries, then dispatches the
       selected entry by a branch table:
           pushstring <visible title>; ...; call <option renderer>
           ... commit menu ...
           pushglobal/pushstack <selected>; pushint <n>; eq; jmpcond <skip>
           call <body function>
       In this case the split boundary is the body function offset, not the menu
       string offset.  Text content is not used to decide whether a string is a
       chapter; only call shape, function scope, branch dispatch, and body text
       evidence are used.
    """

    def _chapter_string_for_call(self, call_idx: int, argc_map: dict[int, int]) -> tuple[dict | None, list[dict], str]:
        """Return the single pushstring consumed by/near a call.

        Strict stack reconstruction fails for expressions like `pushint 1; neg`,
        so we fall back to the nearest pushstring in the current expression block.
        """
        _target, args = self._call_args_at_index(call_idx, argc_map)
        strings = [a for a in args if a.get("kind") == "string"]
        if len(strings) == 1:
            return strings[0], args, "strict_call_args"
        loose = self._last_pushstring_before_call(call_idx, max_scan=14)
        if loose is not None:
            return loose, args, "loose_expression_scan"
        return None, args, "no_string"

    def _call_has_text_after(self, call_idx: int, text_target: int | None, max_scan: int = 220) -> bool:
        if text_target is None:
            return False
        func_i = self.instructions[call_idx].function_index
        for j in range(call_idx + 1, min(len(self.instructions), call_idx + 1 + max_scan)):
            ins = self.instructions[j]
            if ins.function_index != func_i or (ins.valid and ins.opcode == 0x01):
                break
            if ins.valid and ins.opcode == 0x02 and ins.args and int(ins.args[0]["value"]) == text_target:
                return True
        return False

    def _function_call_targets(self) -> dict[int, set[int]]:
        cache = getattr(self, "_chapter_func_call_targets_cache", None)
        if cache is not None:
            return cache
        out: dict[int, set[int]] = defaultdict(set)
        for ins in self.instructions:
            if ins.valid and ins.opcode == 0x02 and ins.args and ins.function_index is not None:
                out[int(ins.function_index)].add(int(ins.args[0]["value"]))
        self._chapter_func_call_targets_cache = out
        return out

    def _function_has_target_call(self, func_i: int | None, target: int) -> bool:
        if func_i is None:
            return False
        return target in self._function_call_targets().get(int(func_i), set())

    def _function_dialogue_counts(self, dialogue_events: list[dict]) -> Counter:
        c: Counter[int] = Counter()
        for ev in dialogue_events:
            fi = ev.get("function_index")
            if fi is not None:
                c[int(fi)] += 1
        return c

    def _scan_route_dispatch_cases(self, start_idx: int, func_i: int | None, max_scan: int = 900) -> list[dict]:
        """Scan selected-index branch table after a menu commit.

        Pattern accepted:
          pushglobal/pushstack X; pushint N; eq; jmpcond SKIP; call BODY
        Optional `call; ret`, `call; jmp END` etc. after BODY are irrelevant.
        """
        rows: list[dict] = []
        end = min(len(self.instructions), start_idx + max_scan)
        for j in range(start_idx, end):
            ins = self.instructions[j]
            if ins.function_index != func_i:
                break
            if ins.valid and ins.opcode == 0x01:
                break
            seq = self.instructions[j:j + 5]
            if len(seq) < 5 or not all(x.valid for x in seq):
                continue
            if not (seq[0].opcode in (0x0F, 0x10) and seq[1].opcode in (0x0A, 0x0B, 0x0C)
                    and seq[2].opcode == 0x22 and seq[3].opcode == 0x07 and seq[4].opcode == 0x02):
                continue
            body_target = int(seq[4].args[0]["value"])
            body_func = self.function_id_for_offset(body_target, exact=True)
            rows.append({
                "case_index": int(seq[1].args[0]["value"]),
                "selector_source": seq[0].mnemonic,
                "selector_slot": int(seq[0].args[0]["value"]) if seq[0].args else None,
                "case_offset": seq[0].offset,
                "case_offset_hex": f"0x{seq[0].offset:08X}",
                "skip_offset": int(seq[3].args[0]["value"]),
                "skip_offset_hex": f"0x{int(seq[3].args[0]['value']):08X}",
                "body_call_offset": seq[4].offset,
                "body_call_offset_hex": f"0x{seq[4].offset:08X}",
                "body_function_offset": body_target,
                "body_function_offset_hex": f"0x{body_target:08X}",
                "body_function_index": body_func,
            })
        # Keep stable source order; duplicate case ids can happen in debug menus, but
        # order is still the only opcode-level relation to the visible option rows.
        return rows

    def _route_groups_for_target(self, target: int, st: dict) -> list[dict]:
        # Reuse the candidate call list built in _infer_chapter_events.  Do not
        # rescan the whole instruction stream per target; large HCBs have close to
        # a million opcodes.
        calls_by_func: dict[int, list[tuple[int, Any, dict, list[dict], str]]] = defaultdict(list)
        for rec in st.get("calls", []):
            _idx, ins, _sarg, _args, _arg_rule = rec
            calls_by_func[int(ins.function_index or 0)].append(rec)

        groups: list[dict] = []
        for func_i, calls in calls_by_func.items():
            calls.sort(key=lambda x: x[0])
            run: list[tuple[int, Any, dict, list[dict], str]] = []
            last_i: int | None = None
            for rec in calls:
                idx = rec[0]
                if run and last_i is not None and idx - last_i > 90:
                    if len(run) >= 2:
                        groups.append(self._make_route_group(target, func_i, run))
                    run = []
                run.append(rec)
                last_i = idx
            if len(run) >= 2:
                groups.append(self._make_route_group(target, func_i, run))
        return [g for g in groups if g]

    def _make_route_group(self, target: int, func_i: int, run: list[tuple[int, Any, dict, list[dict], str]]) -> dict:
        start_idx = run[-1][0] + 1
        # The commit/finalize call is normally the first zero-arg call after the run,
        # but some tables dispatch without a clear commit.  Scan from the run tail in
        # both cases.
        argc_map = self._function_arg_counts()
        commit_idx = None
        for j in range(start_idx, min(len(self.instructions), start_idx + 80)):
            ins = self.instructions[j]
            if ins.function_index != func_i:
                break
            if ins.valid and ins.opcode == 0x02 and ins.args and argc_map.get(int(ins.args[0]["value"])) == 0:
                commit_idx = j
                break
        scan_start = (commit_idx + 1) if commit_idx is not None else start_idx
        cases = self._scan_route_dispatch_cases(scan_start, func_i)
        return {
            "target": target,
            "target_hex": f"0x{target:08X}",
            "function_index": func_i,
            "count": len(run),
            "calls": run,
            "commit_index": commit_idx,
            "commit_offset_hex": f"0x{self.instructions[commit_idx].offset:08X}" if commit_idx is not None else "",
            "cases": cases,
        }

    def _infer_body_title_chapters(self, candidates: dict[int, dict], argc_map: dict[int, int], text_target: int | None) -> list[dict]:
        scored: list[tuple[int, int, int, int]] = []
        for target, st in candidates.items():
            argc = argc_map.get(target)
            calls = len(st["calls"])
            funcs = len(st["funcs"])
            if argc not in (2, 3):
                continue
            if calls < 3 or funcs < 2 or calls > 260:
                continue
            call_indices = [x[0] for x in st["calls"]]
            adjacent = self._target_has_adjacent_menu_runs(call_indices, target)
            max_per_func = max(st["func_counts"].values() or [0])
            # Body title renderers are distributed across body functions; route/menu
            # tables are dense runs in one/few functions.
            if adjacent:
                # Dense consecutive calls in a function are menu/selection tables,
                # not body-title renderers.  They are handled separately by the
                # route-table detector only when a real dispatch -> body function
                # mapping exists.
                continue
            after_text = st["after_text"]
            if after_text < max(2, min(calls, 8) // 2):
                continue
            loose_bonus = st["arg_rules"].get("loose_expression_scan", 0) * 5
            score = after_text * 1400 + funcs * 1000 + min(calls, 200) * 10 + loose_bonus - max_per_func * 50
            scored.append((score, funcs, calls, target))
        if not scored:
            return []
        scored.sort(reverse=True)
        chapter_target = scored[0][3]
        st = candidates[chapter_target]
        rows: list[dict] = []
        for _i, call_ins, sarg, _args, arg_rule in sorted(st["calls"], key=lambda x: x[1].offset):
            title = str(sarg.get("text", ""))
            if not title.strip():
                continue
            rows.append({
                "file": self.file,
                "event_id": len(rows) + 1,
                "event_type": "chapter_title",
                "tag": "chapter",
                "chapter_id": f"chapter_{len(rows) + 1:05d}",
                "function_index": call_ins.function_index,
                "chapter_call_offset": call_ins.offset,
                "chapter_call_offset_hex": f"0x{call_ins.offset:08X}",
                "chapter_target": chapter_target,
                "chapter_target_hex": f"0x{chapter_target:08X}",
                "instruction_offset": sarg.get("instruction_offset"),
                "instruction_offset_hex": sarg.get("instruction_offset_hex"),
                "text_string_data_offset": sarg.get("data_offset"),
                "text_string_data_offset_hex": sarg.get("data_offset_hex"),
                "text_len": sarg.get("len"),
                "title": title,
                "text": title,
                "confidence": "high",
                "detect_rule": "body_function_title_opcode_call",
                "arg_rule": arg_rule,
                "chapter_start_offset": call_ins.offset,
                "chapter_start_offset_hex": f"0x{call_ins.offset:08X}",
            })
        return rows

    def _infer_route_table_chapters(self, candidates: dict[int, dict], argc_map: dict[int, int], dialogue_events: list[dict]) -> list[dict]:
        dialogue_counts = self._function_dialogue_counts(dialogue_events)
        candidate_groups: list[tuple[int, int, dict]] = []
        for target, st in candidates.items():
            argc = argc_map.get(target)
            if argc not in (2, 3):
                continue
            calls = len(st["calls"])
            if calls < 2 or calls > 260:
                continue
            call_indices = [x[0] for x in st["calls"]]
            adjacent = self._target_has_adjacent_menu_runs(call_indices, target)
            max_per_func = max(st["func_counts"].values() or [0])
            if not adjacent and max_per_func < 3:
                continue
            for g in self._route_groups_for_target(target, st):
                if len(g["calls"]) < 2 or not g["cases"]:
                    continue
                # Pair visible rows with branch cases by source order, then keep rows
                # whose branch goes to a function that actually contains dialogue and
                # is not simply another page/table for the same option renderer.
                paired: list[dict] = []
                for rec, case in zip(g["calls"], g["cases"]):
                    _idx, call_ins, sarg, _args, arg_rule = rec
                    body_fi = case.get("body_function_index")
                    if body_fi is None:
                        continue
                    if self._function_has_target_call(body_fi, target):
                        # Another menu page/debug page, not a chapter body.
                        continue
                    text_count = int(dialogue_counts.get(int(body_fi), 0))
                    if text_count <= 0:
                        continue
                    paired.append({
                        "rec": rec,
                        "case": case,
                        "text_count": text_count,
                        "arg_rule": arg_rule,
                    })
                if len(paired) < 2:
                    continue
                total_text = sum(p["text_count"] for p in paired)
                # Large body text coverage is a structural signal that this is a
                # route/chapter table, not a small settings/debug menu.
                score = total_text * 100 + len(paired) * 1000 + max_per_func * 10
                candidate_groups.append((score, len(paired), target, {**g, "paired": paired, "total_body_text": total_text}))
        if not candidate_groups:
            return []
        candidate_groups.sort(reverse=True, key=lambda x: (x[0], x[1]))
        group = candidate_groups[0][3]
        rows: list[dict] = []
        for p in sorted(group["paired"], key=lambda x: x["case"].get("body_function_offset") or 0):
            _idx, call_ins, sarg, _args, arg_rule = p["rec"]
            case = p["case"]
            title = str(sarg.get("text", ""))
            rows.append({
                "file": self.file,
                "event_id": len(rows) + 1,
                "event_type": "chapter_title",
                "tag": "chapter",
                "chapter_id": f"chapter_{len(rows) + 1:05d}",
                "function_index": call_ins.function_index,
                "chapter_call_offset": call_ins.offset,
                "chapter_call_offset_hex": f"0x{call_ins.offset:08X}",
                "chapter_target": group["target"],
                "chapter_target_hex": group["target_hex"],
                "instruction_offset": sarg.get("instruction_offset"),
                "instruction_offset_hex": sarg.get("instruction_offset_hex"),
                "text_string_data_offset": sarg.get("data_offset"),
                "text_string_data_offset_hex": sarg.get("data_offset_hex"),
                "text_len": sarg.get("len"),
                "title": title,
                "text": title,
                "confidence": "medium",
                "detect_rule": "route_table_function_dispatch_call",
                "arg_rule": arg_rule,
                "chapter_start_offset": case.get("body_function_offset"),
                "chapter_start_offset_hex": case.get("body_function_offset_hex", ""),
                "chapter_body_function_index": case.get("body_function_index"),
                "chapter_body_call_offset_hex": case.get("body_call_offset_hex", ""),
                "route_case_index": case.get("case_index"),
                "route_commit_offset_hex": group.get("commit_offset_hex", ""),
                "body_text_count": p.get("text_count", 0),
            })
        return rows


    def _dialogue_first_by_function(self, dialogue_events: list[dict]) -> dict[int, dict]:
        first: dict[int, dict] = {}
        for ev in dialogue_events:
            fi = ev.get("function_index")
            if fi is None:
                continue
            fi = int(fi)
            old = first.get(fi)
            if old is None or int(ev.get("instruction_offset") or 0) < int(old.get("instruction_offset") or 0):
                first[fi] = ev
        return first

    def _dispatcher_body_call_candidates(self, dialogue_events: list[dict], min_body_text: int = 10) -> tuple[list[dict], list[dict]]:
        """Find top-level dispatchers that call real body functions.

        This is the fallback used for Hoshimemo-like scripts where no explicit
        chapter-title string exists.  It is still structural: function call graph +
        body dialogue density.  It does not look at chapter keywords.
        """
        dialogue_counts = self._function_dialogue_counts(dialogue_events)
        first_by_func = self._dialogue_first_by_function(dialogue_events)
        body_funcs = {int(fi) for fi, n in dialogue_counts.items() if int(n) >= min_body_text}
        if not body_funcs:
            return [], []

        calls_by_caller: dict[int, list[dict]] = defaultdict(list)
        for ins in self.instructions:
            if not (ins.valid and ins.opcode == 0x02 and ins.args and ins.function_index is not None):
                continue
            target = int(ins.args[0]["value"])
            body_fi = self.function_id_for_offset(target, exact=True)
            if body_fi is None or int(body_fi) not in body_funcs:
                continue
            if int(body_fi) == int(ins.function_index):
                continue
            first_ev = first_by_func.get(int(body_fi), {})
            calls_by_caller[int(ins.function_index)].append({
                "body_function_index": int(body_fi),
                "body_function_offset": target,
                "body_function_offset_hex": f"0x{target:08X}",
                "body_call_offset": int(ins.offset),
                "body_call_offset_hex": f"0x{ins.offset:08X}",
                "body_text_count": int(dialogue_counts.get(int(body_fi), 0)),
                "first_text": str(first_ev.get("text", "")),
                "first_instruction_offset": first_ev.get("instruction_offset"),
                "first_instruction_offset_hex": first_ev.get("instruction_offset_hex", ""),
                "first_text_len": first_ev.get("text_len"),
                "first_text_string_data_offset": first_ev.get("text_string_data_offset"),
                "first_text_string_data_offset_hex": first_ev.get("text_string_data_offset_hex", ""),
            })

        candidates: list[dict] = []
        for caller_fi, calls in calls_by_caller.items():
            # Collapse duplicate calls to the same body function inside the dispatcher.
            seen: set[int] = set()
            uniq: list[dict] = []
            for c in sorted(calls, key=lambda x: x["body_call_offset"]):
                bfi = int(c["body_function_index"])
                if bfi in seen:
                    continue
                seen.add(bfi)
                uniq.append(c)
            if len(uniq) < 2:
                continue
            total_text = sum(int(c["body_text_count"]) for c in uniq)
            candidates.append({
                "dispatcher_function_index": int(caller_fi),
                "dispatcher_function_offset": self.func_offsets[int(caller_fi)],
                "dispatcher_function_offset_hex": f"0x{self.func_offsets[int(caller_fi)]:08X}",
                "body_call_count": len(uniq),
                "total_body_text": total_text,
                "calls": uniq,
            })
        candidates.sort(key=lambda g: (g["total_body_text"], g["body_call_count"]), reverse=True)

        selected: list[dict] = []
        covered: set[int] = set()
        for g in candidates:
            body_ids = {int(c["body_function_index"]) for c in g["calls"]}
            new_ids = body_ids - covered
            if len(new_ids) < 2:
                continue
            new_text = sum(int(c["body_text_count"]) for c in g["calls"] if int(c["body_function_index"]) in new_ids)
            # Keep top-level dispatchers; skip nested clones that add little new body text.
            if selected and new_text < max(200, int(g["total_body_text"] * 0.35)):
                continue
            kept_calls = [c for c in g["calls"] if int(c["body_function_index"]) in new_ids]
            selected.append({**g, "calls": kept_calls, "new_body_call_count": len(kept_calls), "new_body_text": new_text})
            covered.update(new_ids)
            if len(selected) >= 4:
                break
        return selected, candidates[:12]

    def _infer_dispatcher_scene_chapters(self, dialogue_events: list[dict]) -> tuple[list[dict], dict]:
        selected, top_candidates = self._dispatcher_body_call_candidates(dialogue_events)
        total_scene_calls = sum(len(g.get("calls", [])) for g in selected)
        total_scene_text = sum(int(g.get("new_body_text", 0)) for g in selected)
        probe = {
            "rule": "dispatcher_scene_function_call_probe",
            "selected_dispatchers": [
                {
                    "dispatcher_function_index": g.get("dispatcher_function_index"),
                    "dispatcher_function_offset_hex": g.get("dispatcher_function_offset_hex"),
                    "scene_functions": len(g.get("calls", [])),
                    "body_text": g.get("new_body_text", 0),
                    "sample_scenes": [
                        {
                            "body_function_index": c.get("body_function_index"),
                            "body_function_offset_hex": c.get("body_function_offset_hex"),
                            "body_text_count": c.get("body_text_count"),
                            "first_text": c.get("first_text", "")[:80],
                        }
                        for c in g.get("calls", [])[:16]
                    ],
                }
                for g in selected
            ],
            "top_dispatcher_candidates": [
                {
                    "dispatcher_function_index": g.get("dispatcher_function_index"),
                    "dispatcher_function_offset_hex": g.get("dispatcher_function_offset_hex"),
                    "scene_functions": g.get("body_call_count"),
                    "body_text": g.get("total_body_text"),
                    "sample_scenes": [
                        {
                            "body_function_index": c.get("body_function_index"),
                            "body_function_offset_hex": c.get("body_function_offset_hex"),
                            "body_text_count": c.get("body_text_count"),
                            "first_text": c.get("first_text", "")[:80],
                        }
                        for c in g.get("calls", [])[:10]
                    ],
                }
                for g in top_candidates
            ],
            "scene_count": total_scene_calls,
            "scene_text_count": total_scene_text,
        }
        # Hoshimemo-like: a small set of large body functions; useful as chapter/scene split.
        # hime-like: hundreds of small state-machine scenes; do not export them as fake chapters by default.
        if total_scene_calls <= 0:
            return [], probe
        if total_scene_calls > 80:
            probe["status"] = "SCENE_LEVEL_ONLY_TOO_MANY_FOR_CHAPTER_EXPORT"
            probe["reason"] = "only dispatcher/scene functions were found; exporting them as chapters would create too many non-chapter scene files"
            return [], probe

        rows: list[dict] = []
        ordered_calls: list[dict] = []
        for g in selected:
            ordered_calls.extend(g.get("calls", []))
        ordered_calls.sort(key=lambda c: int(c.get("body_function_offset") or 0))
        for c in ordered_calls:
            first_text = str(c.get("first_text", "")).strip()
            if not first_text:
                continue
            rows.append({
                "file": self.file,
                "event_id": len(rows) + 1,
                "event_type": "chapter_title",
                "tag": "chapter",
                "chapter_id": f"chapter_{len(rows) + 1:05d}",
                "function_index": c.get("body_function_index"),
                "chapter_call_offset": c.get("body_call_offset"),
                "chapter_call_offset_hex": c.get("body_call_offset_hex", ""),
                "chapter_target": c.get("body_function_offset"),
                "chapter_target_hex": c.get("body_function_offset_hex", ""),
                "instruction_offset": c.get("first_instruction_offset"),
                "instruction_offset_hex": c.get("first_instruction_offset_hex", ""),
                "text_string_data_offset": c.get("first_text_string_data_offset"),
                "text_string_data_offset_hex": c.get("first_text_string_data_offset_hex", ""),
                "text_len": c.get("first_text_len"),
                "title": first_text[:60],
                "text": first_text,
                "confidence": "medium",
                "detect_rule": "dispatcher_scene_function_call",
                "arg_rule": "first_dialogue_as_scene_boundary_marker",
                "chapter_start_offset": c.get("body_function_offset"),
                "chapter_start_offset_hex": c.get("body_function_offset_hex", ""),
                "chapter_body_function_index": c.get("body_function_index"),
                "chapter_body_call_offset_hex": c.get("body_call_offset_hex", ""),
                "body_text_count": c.get("body_text_count", 0),
                "patchable": "false",
                "note": "synthetic chapter boundary from dispatcher -> body function; first dialogue is duplicated as a marker and remains patchable in its normal text row",
            })
        probe["status"] = "PASS" if rows else "NO_SCENE_MARKERS"
        probe["exported_scene_chapters"] = len(rows)
        return rows, probe

    def _chapter_candidate_diagnosis(self, candidates: dict[int, dict], argc_map: dict[int, int], limit: int = 24) -> list[dict]:
        rows: list[dict] = []
        for target, st in candidates.items():
            calls = len(st["calls"])
            if calls <= 0:
                continue
            call_indices = [x[0] for x in st["calls"]]
            rows.append({
                "target": target,
                "target_hex": f"0x{target:08X}",
                "argc": argc_map.get(target),
                "calls": calls,
                "functions": len(st["funcs"]),
                "max_calls_in_one_function": max(st["func_counts"].values() or [0]),
                "adjacent_menu_like": self._target_has_adjacent_menu_runs(call_indices, target),
                "after_text_calls": st.get("after_text", 0),
                "arg_rules": dict(st.get("arg_rules", {})),
                "samples": st.get("samples", [])[:12],
            })
        rows.sort(key=lambda r: (r["after_text_calls"], r["functions"], r["calls"]), reverse=True)
        return rows[:limit]

    def _infer_chapter_events(self, argc_map: dict[int, int], text_target: int | None, name_target: int | None,
                              choice_events: list[dict], dialogue_events: list[dict]) -> list[dict]:
        excluded_targets = {t for t in (text_target, name_target) if t is not None}
        excluded_targets.update(
            int(e["choice_render_target"])
            for e in choice_events
            if e.get("choice_render_target") is not None
        )

        candidates: dict[int, dict] = defaultdict(lambda: {
            "calls": [],
            "funcs": set(),
            "func_counts": Counter(),
            "samples": [],
            "after_text": 0,
            "arg_rules": Counter(),
        })

        for i, ins in enumerate(self.instructions):
            if not ins.valid or ins.opcode != 0x02 or not ins.args:
                continue
            target = int(ins.args[0]["value"])
            if target in excluded_targets:
                continue
            argc = argc_map.get(target)
            if argc not in (2, 3):
                continue
            sarg, args, arg_rule = self._chapter_string_for_call(i, argc_map)
            if sarg is None:
                continue
            text = str(sarg.get("text", ""))
            if not text.strip() or self._is_internal_string_arg(text):
                continue
            st = candidates[target]
            st["calls"].append((i, ins, sarg, args, arg_rule))
            if ins.function_index is not None:
                st["funcs"].add(int(ins.function_index))
                st["func_counts"][int(ins.function_index)] += 1
            if len(st["samples"]) < 16:
                st["samples"].append(text)
            if self._call_has_text_after(i, text_target):
                st["after_text"] += 1
            st["arg_rules"][arg_rule] += 1

        body_events = self._infer_body_title_chapters(candidates, argc_map, text_target)
        if body_events:
            self._chapter_diagnosis_cache = {
                "status": "PASS",
                "selected_rule": body_events[0].get("detect_rule"),
                "selected_target_hex": body_events[0].get("chapter_target_hex"),
                "chapters": len(body_events),
                "candidates": self._chapter_candidate_diagnosis(candidates, argc_map),
            }
            return body_events

        route_events = self._infer_route_table_chapters(candidates, argc_map, dialogue_events)
        if route_events:
            self._chapter_diagnosis_cache = {
                "status": "PASS",
                "selected_rule": route_events[0].get("detect_rule"),
                "selected_target_hex": route_events[0].get("chapter_target_hex"),
                "chapters": len(route_events),
                "candidates": self._chapter_candidate_diagnosis(candidates, argc_map),
            }
            return route_events

        scene_events, scene_probe = self._infer_dispatcher_scene_chapters(dialogue_events)
        if scene_events:
            self._chapter_diagnosis_cache = {
                "status": "PASS",
                "selected_rule": scene_events[0].get("detect_rule"),
                "selected_target_hex": "",
                "chapters": len(scene_events),
                "candidates": self._chapter_candidate_diagnosis(candidates, argc_map),
                "dispatcher_scene_probe": scene_probe,
                "warning": "no explicit chapter-title string was found; boundaries are dispatcher -> body function scene splits, not editable title slots",
            }
            return scene_events

        self._chapter_diagnosis_cache = {
            "status": "FAIL_SCENE_LEVEL_ONLY" if scene_probe.get("scene_count", 0) else "FAIL",
            "reason": scene_probe.get("reason") or "no opcode/function chapter evidence strong enough; no fallback all-text export is allowed",
            "selected_rule": "",
            "selected_target_hex": "",
            "chapters": 0,
            "candidates": self._chapter_candidate_diagnosis(candidates, argc_map),
            "dispatcher_scene_probe": scene_probe,
        }
        return []
