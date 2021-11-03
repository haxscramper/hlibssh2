const
  libssh2LinkMode* {.strdefine.} = "dynlib"
  libssh2Lib* {.strdefine.} = "libssh2.so"

import std/[macros]

macro ssh2Proc*(a: untyped): untyped =
  result = a
  result.addPragma(ident"importc")
  when libssh2LinkMode == "dynlib":
    result.addPragma(nnkExprColonExpr.newTree(
      ident"dynlib", ident"libssh2Lib"))

  elif libssh2LinkMode == ["static", "dlink"]:
    # Default dynamic or static linking
    discard

  else:
    {.error: "Invalid libssh2 link mode specified" &
      " expected 'dynlib', 'static' or 'dlink', but got " &
      libssh2LinkMode.}





type
  LIBSSH2_CHANNEL*     {.importc, incompleteStruct.} = object
  LIBSSH2_LISTENER*    {.importc, incompleteStruct.} = object
  LIBSSH2_SESSION*     {.importc, incompleteStruct.} = object
  LIBSSH2_KNOWNHOSTS*  {.importc, incompleteStruct.} = object
  LIBSSH2_AGENT*       {.importc, incompleteStruct.} = object
  LIBSSH2_PUBLICKEY*   {.importc, incompleteStruct.} = object
  LIBSSH2_SFTP_HANDLE* {.importc, incompleteStruct.} = object
  LIBSSH2_SFTP*        {.importc, incompleteStruct.} = object

  off_t* = csize_t
  time_t* = uint64
  stat* = csize_t
