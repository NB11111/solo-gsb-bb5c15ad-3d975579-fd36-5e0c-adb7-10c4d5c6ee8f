"""DNS 别名链发布预检（不落库）。

输入为区域名、**扁平 CNAME/DNAME 记录列表**（每条为 ``(owner, type, class,
ttl, rdata)`` 五元组，规范化由请求模型完成：属主名小写无尾点、类型/类大写、
rdata 为规范化后的别名目标名）与一组待检查名称。处理规则：

1. **冲突校验**：同一 ``(owner, type)`` 出现不同目标（rdata）时抛
   :class:`AliasConflictError`（API 层转换为 HTTP 422）；完全相同的重复
   记录按一条处理；
2. **逐跳解析**：对每个待检查名称，从该名称起逐跳跟随别名——

   - 当前名称上存在 CNAME 记录时**精确 CNAME 优先**，下一跳即其目标；
   - 否则在**严格祖先**（不含当前名称自身）中选取**最长**（最近）且持有
     DNAME 记录者，把当前名称中的该祖先后缀替换为 DNAME 目标得到下一跳；
   - 两者都不存在时解析终止（``terminal``），并给出终止名是否位于本区；

3. **终止判定**：解析中再次遇到已访问过的名称判为 ``loop``；跟随超过
   ``MAX_HOPS``（32）跳仍未终止判为 ``hop_limit``。

每跳记录规则（cname/dname）、来源（所命中记录的属主名）与结果（重写后的
名称）。整个预检仅在内存中计算，不写入数据库。
"""
from __future__ import annotations

#: 422 detail.reason：同一 owner/type 存在冲突目标
ERR_CONFLICTING_TARGETS = "conflicting_targets"

#: 单个名称允许跟随的最大跳数，超过判为 hop_limit
MAX_HOPS = 32

# 扁平 RR：(owner, type, class, ttl, rdata)，均已规范化
FlatRR = tuple[str, str, str, int, str]


class AliasConflictError(Exception):
    """同一 (owner, type) 存在冲突目标（对应 HTTP 422）。

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


def _build_alias_maps(records: list[FlatRR]) -> tuple[dict[str, str], dict[str, str]]:
    """构建 CNAME/DNAME 查找表（owner → 目标）；冲突目标抛 AliasConflictError。"""
    cname: dict[str, str] = {}
    dname: dict[str, str] = {}
    conflicts: dict[tuple[str, str], set[str]] = {}
    for owner, rtype, _rrclass, _ttl, rdata in records:
        table = cname if rtype == "CNAME" else dname
        existing = table.get(owner)
        if existing is None:
            table[owner] = rdata
        elif existing != rdata:
            conflicts.setdefault((owner, rtype), {existing, rdata}).add(rdata)
    if conflicts:
        detail = [
            {"owner": owner, "type": rtype, "targets": sorted(targets)}
            for (owner, rtype), targets in sorted(conflicts.items())
        ]
        raise AliasConflictError(
            f"{len(detail)} 个 owner/type 存在冲突目标", detail
        )
    return cname, dname


def _longest_dname_ancestor(name: str, dname: dict[str, str]) -> str | None:
    """在严格祖先（不含自身）中选取最长且持有 DNAME 记录者，无则返回 None。"""
    ancestor = name.partition(".")[2]
    while ancestor:
        if ancestor in dname:
            return ancestor
        ancestor = ancestor.partition(".")[2]
    return None


def _resolve_one(
    name: str,
    cname: dict[str, str],
    dname: dict[str, str],
    zone_key: str,
) -> dict:
    """逐跳解析单个名称，返回该名称的结果字典。"""
    visited = {name}
    hops: list[dict] = []
    current = name
    while True:
        # 精确 CNAME 优先
        target = cname.get(current)
        if target is not None:
            rule, source, result = "cname", current, target
        else:
            # 否则选取最长的严格祖先 DNAME 并替换前缀
            ancestor = _longest_dname_ancestor(current, dname)
            if ancestor is None:
                return {
                    "name": name,
                    "outcome": "terminal",
                    "hops": hops,
                    "final": current,
                    "in_zone": _in_zone(current, zone_key),
                }
            rule, source = "dname", ancestor
            target = dname[ancestor]
            prefix = current[: len(current) - len(ancestor) - 1]
            result = f"{prefix}.{target}"
        if len(hops) >= MAX_HOPS:
            return {
                "name": name,
                "outcome": "hop_limit",
                "hops": hops,
                "final": current,
                "in_zone": None,
            }
        hops.append(
            {
                "hop": len(hops) + 1,
                "from": current,
                "rule": rule,
                "source": source,
                "target": target,
                "result": result,
            }
        )
        if result in visited:
            return {
                "name": name,
                "outcome": "loop",
                "hops": hops,
                "final": result,
                "in_zone": None,
            }
        visited.add(result)
        current = result


def check_alias_chains(zone: str, records: list[FlatRR], names: list[str]) -> dict:
    """对每个待检查名称做别名链逐跳解析，返回预检结果；不写库。

    :param zone: 已校验的区域名（比较时规范化为小写无尾点）；
    :param records: 规范化后的扁平 CNAME/DNAME 记录列表
        （``(owner, type, class, ttl, rdata)`` 五元组）；
    :param names: 规范化后的待检查名称列表（结果与提交顺序一致）；
    :return: 含 max_hops、counts 与逐名称 results 的结果字典；
    :raises AliasConflictError: 同一 (owner, type) 存在冲突目标；异常的
        ``conflicts`` 属性携带冲突明细。
    """
    zone_key = zone.rstrip(".").lower()
    cname, dname = _build_alias_maps(records)
    results = [_resolve_one(name, cname, dname, zone_key) for name in names]
    cname_count = sum(1 for record in records if record[1] == "CNAME")
    return {
        "zone": zone,
        "max_hops": MAX_HOPS,
        "counts": {
            "total": len(records),
            "cname": cname_count,
            "dname": len(records) - cname_count,
        },
        "results": results,
        "note": (
            "预检结果仅依据本次请求即时计算，不写入数据库；逐跳解析时精确 "
            "CNAME 优先，否则选取最长的严格祖先 DNAME 并替换前缀；名称重复"
            "判为 loop，超过 32 跳判为 hop_limit，无可用别名时判为 terminal "
            "并给出终止名是否位于本区"
        ),
    }
