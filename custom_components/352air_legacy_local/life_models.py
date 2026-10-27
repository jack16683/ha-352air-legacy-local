# SPDX-License-Identifier: GPL-3.0-or-later
"""Product identities used by 352Life 1.8.1, not claims of control support.

Several retail models share a product key. Keep those labels combined instead
of guessing the exact hardware from an advertised name or an IP address.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LifeProduct:
    """A known 352 product family eligible for local identity discovery."""

    model: str
    name: str


LIFE_PRODUCTS: dict[str, LifeProduct] = {
    "a1YKkIC1BMU": LifeProduct("LIFE_RANGE_HOOD", "RangeHood"),
    "a17OodM0CuL": LifeProduct("LIFE_H520", "H520"),
    "a1uIfk3g1ur": LifeProduct("LIFE_H500", "H500"),
    "a1VJw1Oud8X": LifeProduct("LIFE_G30_G45", "G30 / G45"),
    "a1eg4FzfkZU": LifeProduct("LIFE_Q80", "Q80"),
    "a1CVFKMMJY4": LifeProduct("LIFE_H100", "H100"),
    "a1L1JTVgreO": LifeProduct("LIFE_X89C", "X89C"),
    "a1Ktxpu7com": LifeProduct("LIFE_DR10", "Dr10"),
    "a1eLtLlIKYR": LifeProduct("LIFE_H301", "H301"),
    "a1ixutwiNn7": LifeProduct("LIFE_B420", "B420"),
    "a1o2ZnhLc0x": LifeProduct("LIFE_Z90", "Z90"),
    "a10n269QEvP": LifeProduct("LIFE_Z120", "Z120"),
    "a1Ak3NK5icw": LifeProduct("LIFE_Z70", "Z70"),
    "a1agpspjsbU": LifeProduct("LIFE_Z91", "Z91"),
    "a1gYFnlu4UC": LifeProduct("LIFE_Z122", "Z122"),
    "a16zslBlezp": LifeProduct("LIFE_H400", "H400"),
    "a1tw2yfhNMG": LifeProduct("LIFE_H80", "H80"),
    "a15fOklB1DA": LifeProduct("LIFE_H150", "H150"),
    "a1ZNpm4kF9H": LifeProduct("LIFE_X88", "X88 / X88C"),
    "a1hA1xLgHeZ": LifeProduct("LIFE_PIPE_LINE", "PIPE_LINE"),
    "a1Jref2ui7k": LifeProduct("LIFE_H300", "H300"),
    "a1FnudGno3k": LifeProduct("LIFE_DR03", "Dr03"),
    "a1A09hhvpmQ": LifeProduct("LIFE_S100", "S100"),
    "a1HHQyBBOqh": LifeProduct("LIFE_K10", "K10"),
    "a1lAZKRrLWS": LifeProduct("LIFE_S130", "S130"),
    "a1oV1fokg3y": LifeProduct("LIFE_S106", "S106"),
    "a11S8Iz0VGN": LifeProduct("LIFE_B425HC", "B425HC"),
    "a1WBMd7RruJ": LifeProduct("LIFE_Y109", "Y109 / Y109C"),
    "a13CscjWwrj": LifeProduct("LIFE_SKIN", "Skin"),
    "a16BtLvPGrE": LifeProduct("LIFE_Y100", "Y100 / Y100C"),
    "a1BA5uGK6sf": LifeProduct("LIFE_X86", "X86 / X86C"),
    "a1TNKV3wr7I": LifeProduct("LIFE_X83C_PLUS", "X83C Plus"),
    "a1UZUJNPPSa": LifeProduct("LIFE_X63_X66", "X63C / X66C"),
    "a1Kyjc2ZdBQ": LifeProduct("LIFE_X63_PET", "X63C Pet"),
    "a12HMonUBUh": LifeProduct("LIFE_X86_PRO", "X86 Pro"),
}

LIFE_MODEL_OPTIONS = {
    product.model: f"{product.name} (352Life)" for product in LIFE_PRODUCTS.values()
}
