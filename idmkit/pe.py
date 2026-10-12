"""PE 文件的字节级操作。

这一层只关心"在哪里改、改得对不对"，不含任何业务判断。
"""

from __future__ import annotations

from dataclasses import dataclass


class PatchError(Exception):
    """应当中止写入的错误。任何 PatchError 都意味着目标文件保持原样。"""


def find_all(haystack: bytes, needle: bytes, start: int = 0) -> list[int]:
    """返回 needle 在 haystack 中出现的全部起始偏移。"""
    if not needle:
        return []
    hits: list[int] = []
    i = haystack.find(needle, start)
    while i != -1:
        hits.append(i)
        i = haystack.find(needle, i + 1)
    return hits


def find_unique(haystack: bytes, needle: bytes, what: str) -> int:
    """定位唯一锚点；命中数不为 1 时中止。

    这条规则是整套工具的安全底线：锚点唯一性既是"这是目标版本"的证据，
    也是"改这里是对的"的证据。命中 0 次说明版本不对，命中多次说明无法
    确定位置 —— 两种情况都必须放弃，而不是挑第一个碰运气。
    """
    hits = find_all(haystack, needle)
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise PatchError(f"{what}：找不到锚点，该文件不是目标版本。")
    raise PatchError(
        f"{what}：锚点命中 {len(hits)} 次，无法确定改写位置，已放弃。"
    )


def hex_at(data: bytes, start: int, length: int) -> str:
    """把一段字节渲染成大写十六进制，便于写进报告。"""
    chunk = data[start:start + length]
    return " ".join(f"{b:02X}" for b in chunk)


def ensure_writable(data: bytes, at: int, length: int, what: str, size: int) -> None:
    """确认改写范围落在文件内。越界直接中止，不做任何截断或补齐。"""
    if at < 0 or at + length > size:
        raise PatchError(
            f"{what}：改写位置 0x{at:X} 长度 {length} 超出文件边界，已放弃。"
        )


@dataclass(frozen=True)
class Site:
    """一个改写站点。

    anchor      定位用字节串，必须在文件里唯一
    delta       目标位置 = 锚点位置 + delta
    old         原始字节，写入前逐字节比对
    new         替换字节，长度必须与 old 相同
    name        报告里用的名字
    """

    name: str
    anchor: bytes
    delta: int
    old: bytes
    new: bytes

    def __post_init__(self) -> None:
        if len(self.old) != len(self.new):
            raise ValueError(
                f"{self.name}：替换长度 {len(self.new)} 与原始长度 "
                f"{len(self.old)} 不一致，会破坏后续代码布局。"
            )

    @property
    def length(self) -> int:
        return len(self.old)

    def locate(self, data: bytes) -> int:
        return find_unique(data, self.anchor, self.name) + self.delta

    def verify_old(self, data: bytes) -> None:
        """写入前的原始字节比对。不匹配说明文件已被改过，中止。"""
        at = self.locate(data)
        ensure_writable(data, at, self.length, self.name, len(data))
        actual = data[at:at + self.length]
        if actual != self.old:
            raise PatchError(
                f"{self.name}：原始字节不符。\n"
                f"  期望 {self.old.hex(' ').upper()}\n"
                f"  实际 {actual.hex(' ').upper()}\n"
                f"  文件可能已被其他工具改动，已放弃。"
            )
