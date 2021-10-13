import hcparse

startHax()

let
  dir     = AbsDir"/usr/include"
  tmpDir  = getAppTempDir() / "libssh2"
  files   = @[
    dir /. "libssh2.h",
    dir /. "libssh2_sftp.h",
    dir /. "libssh2_publickey.h"
  ]
  map     = expandViaWave(files, tmpDir, baseCParseConf)
  conf    = initCSharedLibFixConf("ssh2", false, dir, map)
  wrapped = tmpDir.wrapViaTs(conf)
  outDir  = currentAbsSourceDir()
  grouped = writeFiles(outDir, wrapped, cCodegenConf)

validateGenerated(grouped)
echo "done"
