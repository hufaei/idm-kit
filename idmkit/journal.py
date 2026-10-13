"""操作记录：把每次动作的结果与失败原因留在磁盘上。

解决的问题：诊断报告只描述「现在是什么状态」。激活失败时，错误提示只出现在
弹窗里，用户关掉就没了 —— 事后导出诊断，只能看到「还没处理过」，排障的人
无法区分是权限被拒、IDM 没关、还是文件被占用。

设计上的两条铁律：

1. **记录失败不能影响主流程。** 每个写入点都吞掉自己的异常。日志是辅助，
   写不进去顶多丢记录，绝不能让本来能成功的激活因为日志而失败。
2. **只追加，不修改。** 用 JSON Lines，坏一行不影响其他行。

存放位置优先 ``%LOCALAPPDATA%\\idm-kit``：这是用户私有目录，不需要管理员
权限，卸载 IDM 或还原官方版都不会牵连它。拿不到就退回 exe 同级。
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

MAX_ENTRIES = 200
"""保留的条目上限。超出后只保留最近的，防止文件无限增长。"""

_DIR_NAME = "idm-kit"
_FILE_NAME = "操作记录.jsonl"


def _fallback_dir() -> Path:
    """拿不到 LOCALAPPDATA 时的退路：exe 所在目录。"""
    try:
        import sys

        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent.parent
    except Exception:
        return Path.cwd()


def log_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA", "").strip()
    if base:
        try:
            d = Path(base) / _DIR_NAME
            d.mkdir(parents=True, exist_ok=True)
            return d
        except OSError:
            pass
    try:
        d = _fallback_dir()
        d.mkdir(parents=True, exist_ok=True)
        return d
    except OSError:
        return _fallback_dir()


def log_path() -> Path:
    return log_dir() / _FILE_NAME


def record(action: str, ok: bool, summary: str = "", detail=None) -> None:
    """记一条。任何异常都被吞掉 —— 见模块开头的第一条铁律。"""
    try:
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "ok": bool(ok),
            "summary": summary,
        }
        if detail:
            entry["detail"] = detail

        p = log_path()
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _trim(p)
    except Exception:
        return


def _trim(path: Path) -> None:
    """条目过多时只留最近的。同样吞异常。"""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if len(lines) <= MAX_ENTRIES:
            return
        kept = [ln for ln in lines[-MAX_ENTRIES:] if ln.strip()]
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    except Exception:
        return


def entries(limit: int = 60) -> list[dict]:
    """读最近若干条。读不到就返回空列表，不抛异常。"""
    out: list[dict] = []
    try:
        p = log_path()
        if not p.is_file():
            return []
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue      # 坏行跳过，不影响其他行
    except Exception:
        return []
    return out[-limit:]


def render_text(limit: int = 60) -> str:
    """给导出报告看的可读版本。"""
    rows = entries(limit)
    if not rows:
        return "没有操作记录。\n\n记录文件位置：" + str(log_path())

    lines = [
        f"最近 {len(rows)} 次操作（新的在最后）：",
        "",
    ]
    for e in rows:
        mark = "成功" if e.get("ok") else "失败"
        lines.append(f"[{e.get('time', '')}] {mark}　{e.get('action', '')}")
        if e.get("summary"):
            lines.append(f"    {e['summary']}")
        detail = e.get("detail")
        if isinstance(detail, dict):
            for k, v in detail.items():
                lines.append(f"    {k} = {v}")
        elif detail:
            lines.append(f"    {detail}")
        lines.append("")

    lines.append(f"记录文件：{log_path()}")
    lines.append(f"上限 {MAX_ENTRIES} 条，超出后自动只留最近的。")
    return "\n".join(lines)
