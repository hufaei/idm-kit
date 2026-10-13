"""补丁的应用、还原与状态判定。

状态一律从文件内容推导，绝不用固定哈希或固定天数当判据 —— 补丁后的哈希
随天数变化，写死任何一个值都会让其他取值被误判成"未知"。
"""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import constants as C
from . import journal
from .pe import (
    PatchError,
    Site,
    checksum_field_offset,
    find_all,
    hex_at,
    pe_checksum,
)

# ---- 站点状态取值 ------------------------------------------------------

APPLIED = "applied"
NOT_APPLIED = "not-applied"
MISSING = "missing"
AMBIGUOUS = "ambiguous"
UNRECOGNISED = "unrecognised"

# ---- 总体状态取值 ------------------------------------------------------

PATCHED = "patched"
PRISTINE = "pristine"
INCONSISTENT = "inconsistent"
PARTIAL = "partial"
UNKNOWN = "unknown"


def make_a_bytes(days: int) -> bytes:
    """mov eax, imm32 ; nop —— 6 字节，与原始算术等长。"""
    return b"\xB8" + days.to_bytes(4, "little") + b"\x90"


def make_b_bytes(days: int) -> bytes:
    """上限在 .data 里的初值。"""
    return days.to_bytes(4, "little")


def build_sites(days: int, include_autoupdate: bool = False) -> list[Site]:
    """构造改写站点。

    A、B、C 是一组，必须一起落地：改了字节就会触发 IDM 的完整性警告并冻结
    下载，所以 C 不是可选项。

    D（取消自动更新）单独一组。它不影响激活，也不改变任何界面行为，是否要
    关掉自动更新由使用者决定，所以默认不打 —— 只有显式要求时才构造。

    ``include_autoupdate=True`` 时即使文件已打过 A、B、C 也没关系：D 有独立
    锚点，写完之后 A、B、C 的锚点依然完好，三个站点各自判定、只写没就位的那几处。
    """
    sites = [
        Site(
            name="补丁 A（上限计算）",
            # 用前缀而不是完整锚点：完整锚点里含着要被改写的那 6 字节，打完之后
            # 它就消失了，续打时无法定位。前缀不含被改部分，打完依然在，靠
            # verify_old 比对中间那 6 字节来判断是否已经改过。
            anchor=C.PREFIX_A,
            delta=C.PATCH_A_AT,
            old=C.PATCH_A_OLD,
            new=make_a_bytes(days),
        ),
        Site(
            name="补丁 B（.data 初值）",
            anchor=C.ANCHOR_B,
            delta=C.ANCHOR_B_DELTA,
            old=C.PATCH_B_OLD,
            new=make_b_bytes(days),
        ),
        Site(
            name="补丁 C（跳过完整性警告）",
            anchor=C.ANCHOR_C,
            delta=C.PATCH_C_AT,
            old=C.PATCH_C_OLD,
            new=C.PATCH_C_NEW,
        ),
    ]
    if include_autoupdate:
        sites.append(
            Site(
                name="补丁 D（取消自动更新判据）",
                anchor=C.ANCHOR_D,
                delta=C.PATCH_D_AT,
                old=C.PATCH_D_OLD,
                new=C.PATCH_D_NEW,
            )
        )
        sites.append(
            Site(
                name="补丁 E（停掉更新定时器分支）",
                anchor=C.ANCHOR_E,
                delta=C.PATCH_E_AT,
                old=C.PATCH_E_OLD,
                new=C.PATCH_E_NEW,
            )
        )
    return sites


# ---- 状态判定 ----------------------------------------------------------


@dataclass
class SiteState:
    state: str
    days: int | None = None
    offset: int = -1
    hits: int = 0


@dataclass
class PatchState:
    overall: str
    days: int | None
    site_a: SiteState
    site_b: SiteState
    site_c: SiteState
    site_d: SiteState | None = None
    site_e: SiteState | None = None
    note: str = ""
    #: 自动更新两个站点的状态说明。
    #: 必须与 note 分开：note 的语义是「这次上限改动有没有实际意义」，
    #: 用它捎带自动更新的信息会让上层把「上限太低」和「更新已关闭」混为一谈。
    auto_note: str = ""

    @property
    def is_patched(self) -> bool:
        return self.overall == PATCHED

    def _au_initialized(self) -> bool:
        """自动更新的两个站点是否都已就位。

        D 只管判据（0x56E93 的阈值），E 才真正停掉那条定时器分支 —— 实测只打
        D 挡不住，所以两者都就位才算「自动更新已取消」。
        """
        return all(
            s is not None and s.state == APPLIED for s in (self.site_d, self.site_e)
        )

    @property
    def autoupdate_stopped(self) -> bool:
        """自动更新是否已被取消（补丁 D 与 E 都就位）。"""
        return self._au_initialized()

    @property
    def autoupdate_known(self) -> bool:
        """两个站点是否都可判定。旧文件或被换过的文件可能找不到它们。"""
        return all(
            s is not None and s.state in (APPLIED, NOT_APPLIED)
            for s in (self.site_d, self.site_e)
        )


def _inspect_site_a(data: bytes) -> SiteState:
    """用补丁后依然存在的前缀定位站点 A，再读它后面的 6 字节。"""
    hits = find_all(data, C.PREFIX_A)
    if not hits:
        return SiteState(MISSING)
    if len(hits) > 1:
        return SiteState(AMBIGUOUS, hits=len(hits))

    at = hits[0]
    mid_at = at + C.PATCH_A_AT
    if mid_at + C.PATCH_A_CODE > len(data):
        return SiteState(UNRECOGNISED, offset=at)

    mid = data[mid_at:mid_at + C.PATCH_A_CODE]
    if mid == C.PATCH_A_OLD:
        return SiteState(NOT_APPLIED, offset=at)
    if mid[0] == 0xB8 and mid[5] == 0x90:
        return SiteState(APPLIED, days=int.from_bytes(mid[1:5], "little"), offset=at)
    return SiteState(UNRECOGNISED, offset=at)


def _inspect_site_d(data: bytes) -> SiteState:
    """读取自动更新周期判定的阈值。

    锚点在目标之前（push edx; push eax; call），不含被改写的 5 字节，所以
    打完之后锚点依然存在，站点可反复定位 —— 与站点 A 用前缀的理由相同。
    """
    hits = find_all(data, C.ANCHOR_D)
    if not hits:
        return SiteState(MISSING)
    if len(hits) > 1:
        return SiteState(AMBIGUOUS, hits=len(hits))

    at = hits[0] + C.PATCH_D_AT
    if at + C.PATCH_D_CODE > len(data):
        return SiteState(UNRECOGNISED, offset=at)

    cur = data[at:at + C.PATCH_D_CODE]
    if cur == C.PATCH_D_OLD:
        return SiteState(NOT_APPLIED, offset=at)
    if cur == C.PATCH_D_NEW:
        return SiteState(APPLIED, offset=at)
    return SiteState(UNRECOGNISED, offset=at)


def _inspect_site_e(data: bytes) -> SiteState:
    """读取消息 5 的分派字节（自动更新那条定时器分支的入口）。

    锚点在目标之前 4 字节，索引表开头的固定 16 字节，不含被改的那一个字节，
    所以改完之后锚点依然命中，站点可反复判定。
    """
    hits = find_all(data, C.ANCHOR_E)
    if not hits:
        return SiteState(MISSING)
    if len(hits) > 1:
        return SiteState(AMBIGUOUS, hits=len(hits))

    at = hits[0] + C.PATCH_E_AT
    if at + C.PATCH_E_CODE > len(data):
        return SiteState(UNRECOGNISED, offset=at)

    cur = data[at:at + C.PATCH_E_CODE]
    if cur == C.PATCH_E_OLD:
        return SiteState(NOT_APPLIED, offset=at)
    if cur == C.PATCH_E_NEW:
        return SiteState(APPLIED, offset=at)
    return SiteState(UNRECOGNISED, offset=at)


def _inspect_site_b(data: bytes, a: SiteState) -> SiteState:
    """读取 .data 中上限的初值。

    与站点 A 的一致性必须先判。官方 .data 初值本来就是 30，所以用
    ``--days 30`` 时站点 A 会被改写而这里改不动（值已经相同），先判 30
    会把这个文件误报成"未打补丁"。
    """
    hits = find_all(data, C.ANCHOR_B)
    if not hits:
        return SiteState(MISSING)
    if len(hits) > 1:
        return SiteState(AMBIGUOUS, hits=len(hits))

    at = hits[0] + C.ANCHOR_B_DELTA
    if at < 0 or at + C.PATCH_B_LEN > len(data):
        return SiteState(UNRECOGNISED, offset=at)

    days_b = int.from_bytes(data[at:at + C.PATCH_B_LEN], "little")
    if a.days is not None and days_b == a.days:
        return SiteState(APPLIED, days=days_b, offset=at)
    if days_b == C.ORIGINAL_DAYS:
        return SiteState(NOT_APPLIED, days=days_b, offset=at)
    return SiteState(UNRECOGNISED, days=days_b, offset=at)


def _inspect_site_c(data: bytes) -> SiteState:
    """读取完整性警告判断点上的跳转形式。"""
    hits = find_all(data, C.ANCHOR_C)
    if not hits:
        return SiteState(MISSING)
    if len(hits) > 1:
        return SiteState(AMBIGUOUS, hits=len(hits))

    at = hits[0] + C.PATCH_C_AT
    if at + C.PATCH_C_CODE > len(data):
        return SiteState(UNRECOGNISED, offset=at)

    cur = data[at:at + C.PATCH_C_CODE]
    if cur == C.PATCH_C_OLD:
        return SiteState(NOT_APPLIED, offset=at)
    if cur == C.PATCH_C_NEW:
        return SiteState(APPLIED, offset=at)
    return SiteState(UNRECOGNISED, offset=at)


def inspect(data: bytes) -> PatchState:
    """判定补丁状态。只读，不修改传入的数据。"""
    a = _inspect_site_a(data)
    b = _inspect_site_b(data, a)
    c = _inspect_site_c(data)
    d = _inspect_site_d(data)
    e = _inspect_site_e(data)

    # 自动更新的说明要按 D、E 两个站点各自的状态说，不能只看一个 —— 只打了 D
    # 而没打 E 的时候，更新其实照样会发生（实测）。
    parts: list[str] = []
    if d.state == APPLIED:
        parts.append("自动更新判据已关闭")
    elif d.state in (MISSING, AMBIGUOUS, UNRECOGNISED):
        parts.append("自动更新判据点无法识别")
    if e.state == APPLIED:
        parts.append("更新定时器分支已停用")
    elif e.state in (MISSING, AMBIGUOUS, UNRECOGNISED):
        parts.append("更新定时器分派点无法识别")
    auto_note = "，".join(parts)

    if a.state == APPLIED and b.state == APPLIED and c.state == APPLIED:
        if a.days == b.days:
            note = ""
            if a.days is not None and a.days <= C.ORIGINAL_DAYS:
                note = (
                    f"当前上限 {a.days} 天不高于官方默认的 {C.ORIGINAL_DAYS} 天，"
                    "这次修改没有任何效果。"
                )
            return PatchState(PATCHED, a.days, a, b, c, d, e, note, auto_note)
        return PatchState(
            INCONSISTENT, None, a, b, c, d, e,
            f"两处数值不一致（代码 {a.days} / 数据 {b.days}）。", auto_note,
        )

    if (a.state == NOT_APPLIED and b.state == NOT_APPLIED
            and c.state == NOT_APPLIED):
        return PatchState(PRISTINE, None, a, b, c, d, e, "", auto_note)

    # A、B 已就位而 C 未打：这是本工具早期版本的产物。不是错误，但警告框会
    # 一直弹、下载一直被冻结，必须显式提示用户补一次。
    if a.state == APPLIED and b.state == APPLIED and c.state == NOT_APPLIED:
        return PatchState(
            PARTIAL, a.days, a, b, c, d, e,
            "试用上限已改，但完整性警告还没跳过 —— 下载时仍会弹出"
            "「IDM 主程序文件已损坏」并冻结下载。再执行一次即可补齐。",
            auto_note,
        )

    detail = "、".join(
        f"{name}={st.state}"
        for name, st in (("代码", a), ("数据", b), ("警告", c),
                         ("判据", d), ("定时器", e))
    )
    return PatchState(UNKNOWN, None, a, b, c, d, e,
                      f"状态无法判定（{detail}）。", auto_note)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


# ---- 结果对象 ----------------------------------------------------------


@dataclass
class PatchResult:
    ok: bool
    changed: bool
    days: int | None
    sha_before: str
    sha_after: str
    backup: Path | None
    lines: list[str] = field(default_factory=list)
    warning: str = ""
    #: 写入后自动更新是否处于「已取消」状态。None 表示无法确认。
    autoupdate_stopped: bool | None = None


# ---- 执行 --------------------------------------------------------------


def is_pristine(sha: str) -> bool:
    return sha.upper() == C.PRISTINE_SHA256


def apply_patch(
    exe: Path,
    days: int,
    force: bool = False,
    *,
    cancel_autoupdate: bool = False,
) -> PatchResult:
    """apply_patch 的带记录入口。

    记录放在这一层而不是函数体内部：一来函数体里满是提前 return 和 raise，
    逐处插入容易漏；二来界面和命令行都调用这一层，两条路都会留痕。
    """
    try:
        result = _apply_patch_impl(
            exe, days, force=force, cancel_autoupdate=cancel_autoupdate
        )
    except PatchError as exc:
        journal.record(
            "关闭自动更新" if cancel_autoupdate else "激活",
            False,
            str(exc).splitlines()[0],
            {"file": str(exe)},
        )
        raise
    except Exception as exc:      # 未预期的异常也要留下痕迹
        journal.record(
            "关闭自动更新" if cancel_autoupdate else "激活",
            False,
            f"未预期的错误：{exc}",
            {"file": str(exe)},
        )
        raise

    journal.record(
        "关闭自动更新" if cancel_autoupdate else "激活",
        True,
        _result_summary(result),
        {
            "file": str(exe),
            "changed": result.changed,
            "days": result.days,
            "sha_after": result.sha_after[:16] if result.sha_after else "",
            "autoupdate_stopped": result.autoupdate_stopped,
        },
    )
    return result


def _result_summary(result: PatchResult) -> str:
    if not result.changed:
        return "本来就已就位，没有写入"
    parts = [f"上限 {result.days} 天" if result.days else "已改写"]
    if result.autoupdate_stopped:
        parts.append("自动更新已关闭")
    return "，".join(parts)


def _apply_patch_impl(
    exe: Path,
    days: int,
    force: bool = False,
    *,
    cancel_autoupdate: bool = False,
) -> PatchResult:
    """把试用上限改成 days 天；可选地一并取消自动更新。

    所有检查都在写入之前完成；任何一项不通过，文件保持原样。

    ``cancel_autoupdate=True`` 时额外改写自动更新的周期判定（补丁 D）。它与
    上限互不影响：已经激活过的文件上也能单独补打，因为 D 的锚点是独立的。
    """
    if not (1 <= days <= 0xFFFFFFFF):
        raise PatchError(f"天数 {days} 必须是 1 到 4294967295 之间的整数。")
    if not exe.is_file():
        raise PatchError(f"文件不存在：{exe}")

    data = exe.read_bytes()
    sha_before = sha256_of(data)
    lines: list[str] = []

    state = inspect(data)

    # 幂等：先看是不是已经打过了。用补丁后仍存在的前缀定位，不依赖哈希。
    if state.is_patched:
        # 补丁本身已就位，但校验和可能还是旧的：早期版本只改字节、不重算它，
        # 那样的文件会让 IDM 报「主程序文件已损坏」。所以这里不能直接收工。
        #
        # 这里也是补打自动更新补丁的入口：文件早已激活过（A、B、C 就位）而要求
        # 取消自动更新的情形，走的正是这条路径 —— 它的哈希是补丁后的，不可能
        # 等于官方原始哈希，下面的白名单必然拦下它。
        if cancel_autoupdate:
            # 只要有一个自动更新站点还处于「没打」，就继续写；全都打完了才算
            # 没事可做。判据是按站点实际字节读出来的，不依赖任何记号。
            want_d = True
        else:
            want_d = False

        cs_at = checksum_field_offset(data)
        cs_stored = int.from_bytes(data[cs_at:cs_at + 4], "little")
        cs_want = pe_checksum(data)
        checksum_ok = cs_stored == cs_want

        if checksum_ok and not want_d:
            note = ""
            if state.autoupdate_stopped:
                note = "，自动更新已取消"
            elif cancel_autoupdate:
                note = "，但自动更新站点无法识别，没能取消"
            return PatchResult(
                ok=True, changed=False, days=state.days,
                sha_before=sha_before, sha_after=sha_before, backup=None,
                lines=[
                    f"当前上限已经是 {state.days} 天，PE 校验和自洽{note}，无需处理。"
                ],
                autoupdate_stopped=state.autoupdate_stopped,
            )

        sites = (
            [s for s in build_sites(
                state.days or C.DEFAULT_DAYS, include_autoupdate=True)
             if s.name.startswith(("补丁 D", "补丁 E"))]
            if want_d else []
        )
    else:
        # 白名单：只接受未被改动的官方文件。
        #
        # 例外：A、B 已就位而 C 未打 —— 这是本工具早期版本处理过的文件，也正好是
        # 老用户升级工具后会遇到的情形。这种文件放行，只补缺的那一处。打自动更新
        # 补丁时不需要这个例外：那个情形由上面的 is_patched 分支接管。
        resumable = (
            state.site_a.state == APPLIED
            and state.site_b.state == APPLIED
            and state.site_c.state == NOT_APPLIED
        )
        if not is_pristine(sha_before) and not force and not resumable:
            raise PatchError(
                "这个文件不是已知的官方版本，拒绝写入。\n"
                f"  实际 sha256 = {sha_before}\n"
                f"  期望 sha256 = {C.PRISTINE_SHA256}\n"
                "如果确认要处理，请显式选择「强制」。"
            )

        # 续打时沿用文件里已有的天数：用户这次填的值可能与当初不同，以文件为准
        # 才不会让两处数值打架。
        if resumable:
            if state.days is None:
                raise PatchError("文件里的天数读不出来，无法安全续打。")
            days = state.days

        want_d = cancel_autoupdate
        sites = build_sites(days, include_autoupdate=want_d)

    pending: list[Site] = []
    for site in sites:
        at = site.locate(data)
        if data[at:at + site.length] == site.new:
            lines.append(f"{site.name}：已是目标状态，跳过")
            continue
        site.verify_old(data)
        lines.append(f"{site.name}：锚点唯一，将改写 0x{at:X}")
        pending.append(site)

    if not pending and not state.is_patched:
        return PatchResult(
            ok=True, changed=False, days=days,
            sha_before=sha_before, sha_after=sha_before, backup=None,
            lines=lines + ["各补丁站点均已就位，无写入。"],
            autoupdate_stopped=state.autoupdate_stopped,
        )

    # 备份只在首次生成，保留最原始的那一份。
    backup_path = exe.with_name(exe.name + C.BACKUP_SUFFIX)
    backup_made = False
    if not backup_path.exists():
        shutil.copy2(exe, backup_path)
        backup_made = True
        lines.append(f"已备份原始文件到 {backup_path.name}")

    buf = bytearray(data)
    for site in pending:
        at = site.locate(bytes(buf))
        buf[at:at + site.length] = site.new

    # 补丁改的是代码段，PE 头里的 CheckSum 必须跟着重算。IDM 用它做自身完整性
    # 检查：字段与实际内容对不上就报「IDM 主程序文件已损坏」并冻结下载，直到
    # 用户重装。只改字节不重算校验和，等于亲手把这份文件标记成损坏。
    #
    # 这里只在确实需要时写这个字段：幂等分支可能是「校验和本来就对，只是要补
    # 打补丁 D」，那种情况下重算一次会得到同样的值，但没必要多写一次。
    cs_at = checksum_field_offset(bytes(buf))
    cs_old = int.from_bytes(buf[cs_at:cs_at + 4], "little")
    cs_new = pe_checksum(bytes(buf))
    if cs_old != cs_new:
        buf[cs_at:cs_at + 4] = cs_new.to_bytes(4, "little")
        lines.append(f"PE 校验和：0x{cs_old:08X} → 0x{cs_new:08X}")
    else:
        lines.append(f"PE 校验和 0x{cs_old:08X} 本来就自洽，无需改动")

    if not pending:
        return PatchResult(
            ok=True, changed=False, days=days,
            sha_before=sha_before, sha_after=sha_before, backup=None,
            lines=lines + ["没有需要写入的改动。"],
            autoupdate_stopped=state.autoupdate_stopped,
        )

    exe.write_bytes(bytes(buf))

    # 回读校验：确认落盘的字节真的是我们想要的。
    verify = exe.read_bytes()
    after = inspect(verify)
    if not after.is_patched or after.days != days:
        # 只补打补丁 D 时天数不变，但仍然要求文件整体仍是「已激活」状态 ——
        # 否则说明写坏了。
        raise PatchError(
            "写入后的回读校验未通过，文件可能已损坏。\n"
            f"请用备份还原：{backup_path}"
        )

    # 校验和同样要回读确认，否则文件会带着一个自相矛盾的头。
    if int.from_bytes(verify[cs_at:cs_at + 4], "little") != pe_checksum(verify):
        raise PatchError(
            "PE 校验和回读不一致，文件头与实际内容对不上。\n"
            f"请用备份还原：{backup_path}"
        )

    # 自动更新的补丁没生效，属于必须说出来的失败，不能算成功。
    if want_d:
        if not after.site_d or after.site_d.state != APPLIED:
            raise PatchError(
                "自动更新判据点（补丁 D）写入后回读不通过，阈值没有改变。\n"
                f"请用备份还原：{backup_path}"
            )
        if not after.site_e or after.site_e.state != APPLIED:
            raise PatchError(
                "更新定时器分派点（补丁 E）写入后回读不通过，"
                "那条分支仍未停用。\n"
                f"请用备份还原：{backup_path}"
            )

    return PatchResult(
        ok=True, changed=True, days=days,
        sha_before=sha_before, sha_after=sha256_of(verify),
        backup=backup_path if backup_made else backup_path,
        lines=lines,
        autoupdate_stopped=after.autoupdate_stopped,
    )


def restore(exe: Path) -> PatchResult:
    """restore 的带记录入口，理由同 apply_patch。"""
    try:
        result = _restore_impl(exe)
    except PatchError as exc:
        journal.record("还原官方版", False, str(exc).splitlines()[0],
                       {"file": str(exe)})
        raise
    except Exception as exc:
        journal.record("还原官方版", False, f"未预期的错误：{exc}",
                       {"file": str(exe)})
        raise

    journal.record(
        "还原官方版",
        True,
        "已还原" if result.changed else "文件本来就是还原后的样子",
        {
            "file": str(exe),
            "changed": result.changed,
            "sha_after": result.sha_after[:16] if result.sha_after else "",
            "warning": result.warning or "",
        },
    )
    return result


def _restore_impl(exe: Path) -> PatchResult:
    """从 .bak 还原。"""
    backup_path = exe.with_name(exe.name + C.BACKUP_SUFFIX)
    if not backup_path.is_file():
        raise PatchError(
            f"找不到备份文件 {backup_path.name}，无法还原。"
            "备份只在首次处理时生成；没有它就只能重新安装。"
        )

    before = sha256_of(exe.read_bytes()) if exe.is_file() else ""
    shutil.copy2(backup_path, exe)
    after = sha256_of(exe.read_bytes())

    lines = [f"已从 {backup_path.name} 还原。"]
    warning = ""
    if not is_pristine(after):
        warning = (
            "还原后的文件与官方原始版本不一致，备份可能已被替换。"
        )
    return PatchResult(
        ok=True, changed=before != after, days=None,
        sha_before=before, sha_after=after,
        backup=backup_path, lines=lines, warning=warning,
    )
