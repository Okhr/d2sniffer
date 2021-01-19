from typing import List


class ByteArray:
    def __init__(self, init_bytes: bytes):
        self._bytes: List[int] = [b for b in init_bytes]
        self._initial_size: int = len(self._bytes)

    def __len__(self) -> int:
        return self.size()

    def __add__(self, other):
        if type(other) != ByteArray:
            raise TypeError(f"Can't add a ByteArray and a {type(other)}")
        return ByteArray(self._bytes + other.get_bytes())

    def __str__(self) -> str:
        return f"<ByteArray {self.size()}/{self.initial_size()} : {self.get_bytes()}>"

    def __repr__(self) -> str:
        return self.__str__()

    def size(self) -> int:
        return len(self._bytes)

    def initial_size(self) -> int:
        return self._initial_size

    def get_bytes(self) -> bytes:
        return bytes(self._bytes)

    """
    ######################### WRITERS #########################
    """

    def write_byte(self, b: int) -> None:
        if b > 255:
            raise OverflowError
        else:
            self._bytes.append(b)

    def write_short(self, s: int) -> None:
        if s > 65_535:
            raise OverflowError
        else:
            self._bytes.append((s & 0xff00) >> 8)
            self._bytes.append((s & 0x00ff))

    def write_int(self, n: int) -> None:
        if n > 4_294_967_295:
            raise OverflowError
        else:
            self._bytes.append((n & 0xff000000) >> 24)
            self._bytes.append((n & 0x00ff0000) >> 16)
            self._bytes.append((n & 0x0000ff00) >> 8)
            self._bytes.append((n & 0x000000ff))

    def write_utf8(self, s: str) -> None:
        encoded_str: bytes = bytes(s, "utf-8")
        size: int = len(encoded_str)
        self.write_short(size)
        for b in encoded_str:
            self.write_byte(b)

    """
    ######################### READERS #########################
    """

    def read_byte(self) -> int:
        return self._bytes.pop(0)

    def read_n_bytes(self, n: int) -> List[int]:
        result: List[int] = []
        for _ in range(n):
            result.append(self.read_byte())
        return result

    def read_short(self) -> int:
        result: int = int.from_bytes(bytes(self._bytes[:2]), byteorder="big")
        del self._bytes[:2]
        return result

    def read_int(self) -> int:
        result: int = int.from_bytes(bytes(self._bytes[:4]), byteorder="big")
        del self._bytes[:4]
        return result

    def read_utf8(self) -> str:
        size: int = self.read_short()
        result: str = bytes(self._bytes[:size]).decode("utf-8")
        del self._bytes[:size]
        return result
