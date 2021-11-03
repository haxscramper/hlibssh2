import hcparse

startHax()

let
  dir     = AbsDir"/usr/include"
  tmpDir  = getAppTempDir() / "libssh2"
  package = "hlibssh2"
  files   = @[
    dir /. "libssh2.h",
    dir /. "libssh2_sftp.h",
    dir /. "libssh2_publickey.h"
  ]
  map     = expandViaWave(files, tmpDir, baseCParseConf)
  conf    = initCSharedLibFixConf("ssh2", package, false, dir, map)
  wrapped = tmpDir.wrapViaTs(conf).postFixEntries(conf)
  outDir  = currentAbsSourceDir()
  grouped = writeFiles(outDir, wrapped, cCodegenConf, extraTypes = @{
    cxxName("_LIBSSH2_SESSION"): cxxLibImport(package, @["libssh2_config"])
  })

validateGenerated(grouped)
echo "done"
