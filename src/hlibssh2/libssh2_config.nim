const libssh2Dl* {.strdefine.} = "libssh2.so"

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
