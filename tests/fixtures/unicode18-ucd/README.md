# Unicode 18.0.0 character data

`DerivedGeneralCategory.txt` and `EastAsianWidth.txt` are two files of the Unicode Character
Database 18.0.0 (`DerivedGeneralCategory-18.0.0.txt` and `EastAsianWidth-18.0.0.txt`, both dated
2026-06-29 in their headers), published at
https://www.unicode.org/Public/18.0.0/ucd/extracted/DerivedGeneralCategory.txt and
https://www.unicode.org/Public/18.0.0/ucd/EastAsianWidth.txt under the Unicode License v3.
`cargo xtask cell-widths` reads them to write `src/bin/mhfe/cell_widths.rs`, the terminal cells of
each character. They are data of this repository only and are not packaged with the program.
`SHA256SUMS` records their SHA-256, which the task checks before it reads them.

On 2026-11-03 both files were downloaded from those addresses, and the table they give was compared
with the one the earlier generator wrote from the `unicodedata2` 18.0.0 package: all 508 runs are
identical.
