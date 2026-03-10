class Deduplicator:
    """
    Merge-deduplicates findings based on URL + finding_name.
    Keeps highest severity BUT preserves multi-tool evidence:
      - correlation.tools
      - correlation.tool_count
      - evidence_list
      - sources (optional, same as tools)
    """

    SEVERITY_RANK = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    @staticmethod
    def _get_tool_name(finding: dict) -> str:
        # Try common keys used in your pipeline
        for k in ("tool", "original_tool", "scanner", "source"):
            v = finding.get(k)
            if v:
                return str(v).strip().lower()
        return "unknown"

    @staticmethod
    def _safe_str(x) -> str:
        return str(x).strip() if x is not None else ""

    @staticmethod
    def process(findings):
        if not findings:
            return []

        unique_map = {}

        for finding in findings:
            url = Deduplicator._safe_str(finding.get("url", "")).lower()
            name = Deduplicator._safe_str(finding.get("finding_name", "")).lower()
            severity = Deduplicator._safe_str(finding.get("severity", "INFO")).upper()
            tool = Deduplicator._get_tool_name(finding)

            fingerprint = f"{url}|{name}"

            # Ensure evidence is captured consistently
            ev = Deduplicator._safe_str(finding.get("evidence", ""))

            if fingerprint not in unique_map:
                # First time we see this finding → initialize merge fields
                base = dict(finding)

                # evidence_list: keep all evidences across duplicates
                base["evidence_list"] = []
                if ev:
                    base["evidence_list"].append(ev)

                # correlation: track tools contributing to this finding
                base["correlation"] = {
                    "tools": [tool] if tool else [],
                    "tool_count": 1 if tool else 0
                }

                # Optional alias (some people like this field)
                base["sources"] = base["correlation"]["tools"]

                unique_map[fingerprint] = base
                continue

            # Duplicate found → MERGE into existing
            existing = unique_map[fingerprint]

            # Merge evidence
            if ev:
                existing_list = existing.get("evidence_list") or []
                if ev not in existing_list:
                    existing_list.append(ev)
                existing["evidence_list"] = existing_list

            # Merge tools
            corr = existing.get("correlation") or {}
            tools = set(corr.get("tools") or [])
            if tool:
                tools.add(tool)
            tools = sorted(tools)

            existing["correlation"] = {
                "tools": tools,
                "tool_count": len(tools)
            }
            existing["sources"] = tools

            # Keep highest severity (your original logic)
            existing_severity = Deduplicator._safe_str(existing.get("severity", "INFO")).upper()
            existing_rank = Deduplicator.SEVERITY_RANK.get(existing_severity, 1)
            new_rank = Deduplicator.SEVERITY_RANK.get(severity, 1)

            if new_rank > existing_rank:
                # Replace main fields with higher severity one,
                # but keep merged fields (evidence_list/correlation/sources)
                merged_evidence_list = existing.get("evidence_list", [])
                merged_corr = existing.get("correlation", {})
                merged_sources = existing.get("sources", [])

                unique_map[fingerprint] = dict(finding)
                unique_map[fingerprint]["evidence_list"] = merged_evidence_list
                unique_map[fingerprint]["correlation"] = merged_corr
                unique_map[fingerprint]["sources"] = merged_sources
            else:
                # keep existing (already in map)
                unique_map[fingerprint] = existing

        return list(unique_map.values())
