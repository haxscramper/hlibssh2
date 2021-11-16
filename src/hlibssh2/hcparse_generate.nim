import hcparse

startHax()

const useClang = true

let
  dir     = AbsDir"/usr/include"
  tmpDir  = getAppTempDir() / "libssh2"
  package = "hlibssh2"
  files   = @[
    dir /. "libssh2.h",
    dir /. "libssh2_sftp.h",
    dir /. "libssh2_publickey.h"
  ]

  outDir  = currentAbsSourceDir()


let extra = @{
  cxxName("_LIBSSH2_SESSION"): cxxLibImport(package, @["libssh2_config"])
}


if useClang:
  var cache = newWrapCache()

  let
    wrapConf    = baseCppWrapConf.withDeepIt do:
      it.onIgnoreCursor():
        return false

  let
    fixConf     = initCSharedLibFixConf("ssh2", package, false, dir)
    wrapped     = files.wrapViaClang(wrapConf, fixConf, cache, dir)
    postWrapped = wrapped.postFixEntries(fixConf)
    grouped     = writeFiles(
      outDir, postWrapped, cCodegenConf, extraTypes = extra)

  validateGenerated(grouped)
  echo "wrapped validation ok"

else:
  let
    map     = expandViaWave(files, tmpDir, baseCParseConf)
    conf    = initCSharedLibFixConf("ssh2", package, false, dir, map)
    wrapped = tmpDir.wrapViaTs(conf).postFixEntries(conf)
    grouped = writeFiles(outDir, wrapped, cCodegenConf, extraTypes = extra)

  validateGenerated(grouped)
  echo "done"
