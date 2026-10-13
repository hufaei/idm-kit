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


def checksum_field_offset(data: bytes) -> int:
    """返回 OptionalHeader.CheckSum 字段的文件偏移。

    CheckSum 在 OptionalHeader 内部的位置对 PE32 与 PE32+ 都是固定的（偏移 64），
    但 OptionalHeader 自身的起点要靠 e_lfanew 推出来，所以这里不写死任何绝对
    偏移 —— 换一个编译产物依然能定位。
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PatchError("不是 PE 文件：缺少 MZ 头。")
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        raise PatchError(f"PE 头偏移 0x{e_lfanew:X} 越界，文件结构异常。")
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PatchError("不是 PE 文件：缺少 PE 签名。")
    opt = e_lfanew + 24
    opt_size = int.from_bytes(data[e_lfanew + 20:e_lfanew + 22], "little")
    magic = int.from_bytes(data[opt:opt + 2], "little")
    if magic not in (0x10B, 0x20B):
        raise PatchError(f"未知的 OptionalHeader Magic：0x{magic:X}。")
    if opt_size < 68 or opt + 68 > len(data):
        raise PatchError("OptionalHeader 太小，读不到 CheckSum 字段。")
    return opt + 64


def pe_checksum(data: bytes) -> int:
    """按 Windows 的 CheckSumMappedFile 算法计算 PE 校验和。

    规则是把文件按 16 位小端字累加进一个 32 位累加器，每次累加后把高 16 位折回
    低位，最后加上文件长度。CheckSum 字段自身按 0 参与计算，所以同一个函数既能
    算出"应该写进去的值"，也能用来验证已写入的值是否自洽。
    """
    at = checksum_field_offset(data)
    total = 0
    size = len(data)
    i = 0
    while i + 1 < size:
        word = 0 if (i == at or i == at + 2) else (data[i] | (data[i + 1] << 8))
        total += word
        total = (total & 0xFFFF) + (total >> 16)
        i += 2
    if size & 1:
        total += data[size - 1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (total + size) & 0xFFFFFFFF


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
