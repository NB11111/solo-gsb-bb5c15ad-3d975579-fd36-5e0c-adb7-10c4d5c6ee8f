"""DNS 别名链发布预检（不落库）。

输入为区域名、**CNAME/DNAME 记录列表**与**待检查名称列表**（记录与名称
的规范化由请求模型完成）。每个待检查名称独立逐跳解析：

1. **精确 CNAME 优先**：当前名称存在 CNAME 记录时，按该记录目标改写；
2. **最长严格祖先 DNAME**：否则在当前名称的严格祖先（父域、祖父域……）
   中选取最长的、存在 DNAME 记录的属主名，用其目标替换名称中匹配到的
   祖先部分（保留下级相对名）——当前名称自身的 DNAME 不参与匹配
   （DNAME 只作用于严格后代）；
3. **终结**：两者都不存在时解析终结（``terminal``），并报告终结名称
   是否位于本区。

保护规则：解析结果回到本链已访问过的名称时判为 ``loop``；需要超过
``MAX_HOPS``（32）跳才能终结时判为 ``hop_limit``（保留已执行的 32 跳
记录）。每一跳记录规则（``cname``/``dname``）、来源（匹配记录的属主
名）、目标与结果名称。

同一 ``(owner, type)`` 出现不同目标时抛 :class:`AliasConflictError`
（API 层转换为 HTTP 422）。整个预检仅在内存中计算，不写入数据库。
"""
from __future__ import annotations

#: 单个名称解析允许的最大跳数；需要更多跳才能终结时判为 hop_limit
MAX_HOPS = 32

#: 422 detail.reason：同一 owner/type 存在冲突目标
ERR_CONFLICTING_TARGETS = "conflicting_alias_targets"

# 规范化后的别名记录：(owner, type, target)，type ∈ {"CNAME", "DNAME"}
AliasRecord = tuple[str, str, str]


class AliasConflictError(Exception):
    """同一 owner/type 存在冲突目标（对应 HTTP 422）。

    :param conflicts: 冲突明细（``[{"owner": ..., "type": ...,
        "targets": [...]}]``，按 (owner, type) 字典序，targets 升序）。
    """

    def __init__(self, message: str, conflicts: list[dict]) -> None:
        super().__init__(message)
        self.code = ERR_CONFLICTING_TARGETS
        self.conflicts = conflicts


def _in_zone(name: str, zone_key: str) -> bool:
    """判断名字是否位于区域内（等于区域名或为其子域）。"""
    return name == zone_key or name.endswith("." + zone_key)


def _build_alias_maps(
    records: list[AliasRecord],
) -> tuple[dict[str, str], dict[str, str]]:
    """按 (owner, type) 归并目标，返回 (cname_map, dname_map)。

    同一 (owner, type) 的目标完全相同的重复记录视为一条；目标不唯一时
    抛 :class:`AliasConflictError`。
    """
    targets: dict[tuple[str, str], set[str]] = {}
    for owner, rtype, target in records:
        targets.setdefault((owner, rtype), set()).add(target)
    conflicts = [
        {"owner": owner, "type": rtype, "targets": sorted(values)}
        for (owner, rtype), values in sorted(targets.items())
        if len(values) > 1
    ]
    if conflicts:
        raise AliasConflictError(
            f"{len(conflicts)} 个 owner/type 存在冲突目标"
            "（同一属主名与记录类型的目标不唯一）",
            conflicts,
        )
    cname_map = {
        owner: next(iter(values))
        for (owner, rtype), values in targets.items()
        if rtype == "CNAME"
    }
    dname_map = {
        owner: next(iter(values))
        for (owner, rtype), values in targets.items()
        if rtype == "DNAME"
    }
    return cname_map, dname_map


def _longest_dname_source(name: str, dname_map: dict[str, str]) -> str | None:
    """在 name 的严格祖先中选取最长的、存在 DNAME 记录的属主名。"""
    ancestor = name.partition(".")[2]
    while ancestor:
        if ancestor in dname_map:
            return ancestor
        ancestor = ancestor.partition(".")[2]
    return None


def _resolve(
    name: str, cname_map: dict[str, str], dname_map: dict[str, str]
) -> tuple[list[dict], str, str]:
    """逐跳解析单个名称，返回 ``(hops, status, final)``。

    ``final`` 仅在 status 为 ``terminal`` 时有意义（终结名称）；为
    ``loop`` 时重复名称为最后一跳的 ``result``；为 ``hop_limit`` 时
    ``final`` 为达到上限后仍待解析的名称。
    """
    hops: list[dict] = []
    visited = {name}
    current = name
    while True:
        if current in cname_map:
            # 精确 CNAME 优先
            rule, source, target = "cname", current, cname_map[current]
            result = target
        else:
            # 否则选取最长的严格祖先 DNAME
            source = _longest_dname_source(current, dname_map)
            if source is None:
                return hops, "terminal", current
            rule, target = "dname", dname_map[source]
            prefix = current[: -(len(source) + 1)]
            result = f"{prefix}.{target}"
        if len(hops) >= MAX_HOPS:
            return hops, "hop_limit", current
        hops.append(
            {
                "hop": len(hops) + 1,
                "rule": rule,
                "source": source,
                "target": target,
                "result": result,
            }
        )
        if result in visited:
            return hops, "loop", result
        visited.add(result)
        current = result


def check_alias_chains(
    zone: str, records: list[AliasRecord], names: list[str]
) -> dict:
    """对每个待检查名称逐跳解析别名链，返回预检结果；不写库。

    :param zone: 已校验的区域名（比较时规范化为小写无尾点）；
    :param records: 规范化后的别名记录（``(owner, type, target)`` 三元组，
        type ∈ {"CNAME", "DNAME"}）；
    :param names: 规范化后的待检查名称列表；
    :return: 含 results、summary 的结果字典；
    :raises AliasConflictError: 同一 owner/type 存在冲突目标；异常的
        ``conflicts`` 属性携带冲突明细。
    """
    zone_key = zone.rstrip(".").lower()
    cname_map, dname_map = _build_alias_maps(records)

    results: list[dict] = []
    counts = {"terminal": 0, "loop": 0, "hop_limit": 0}
    for name in names:
        hops, status, final = _resolve(name, cname_map, dname_map)
        counts[status] += 1
        terminal = None
        if status == "terminal":
            in_zone = _in_zone(final, zone_key)
            terminal = {"name": final, "in_zone": in_zone}
            message = (
                f"名称终结于 {final}"
                f"（{'位于本区' if in_zone else '不在本区'}），无可用别名记录"
            )
        elif status == "loop":
            message = f"解析结果 {final} 在本链中已访问过，构成别名环"
        else:
            message = f"解析需超过 {MAX_HOPS} 跳才能终结，判定为 hop_limit"
        results.append(
            {
                "name": name,
                "status": status,
                "hops": hops,
                "terminal": terminal,
                "message": message,
            }
        )

    return {
        "zone": zone,
        "results": results,
        "summary": {"total": len(names), **counts},
        "note": (
            "预检结果仅依据本次请求即时计算，不写入数据库；逐跳解析时精确 "
            "CNAME 优先，否则选取最长的严格祖先 DNAME 并用其目标替换匹配到"
            "的祖先部分；名称重复判为 loop，超过 32 跳判为 hop_limit，无可用"
            "别名时为 terminal 并报告终结名称是否位于本区"
        ),
    }
