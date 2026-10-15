# MinGW-w64 runtime notices

The canonical Windows build links runtime objects from Ubuntu's
`mingw-w64-x86-64-dev` package, version `11.0.1-3build1`, selected by the archive snapshot
in `packaging/Dockerfile.reproducible`.

`mingw-w64-runtime-COPYRIGHT` is the unchanged
`/usr/share/doc/mingw-w64-x86-64-dev/copyright` from that package. It retains the complete
package copyright file rather than selecting notices by symbol: the CRT includes public-domain,
Zope Public License 2.1 and Lucent/David M. Gay material, and the file also covers winpthreads
when linked. Entries for components not linked into MHFE are retained too.

The Windows archive ships this file as `licenses/mingw-w64-COPYRIGHT`.
`scripts/mingw_notices.py`, called by `scripts/third-party-licenses.py`, checks its fixed source
hash and, where the development package is installed, compares the installed copyright file.
Its binary/archive gate refuses a MinGW executable without the notice and, in an archive,
without the complete unchanged text. A compiler/snapshot update must repeat this comparison
and review changes to the notices before changing the hash.
