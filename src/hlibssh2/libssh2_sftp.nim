import "./libssh2_config.nim" ## From gen file
import "./libssh2.nim"

type
  _LIBSSH2_SFTP_ATTRIBUTES* {.incompleteStruct.} = object
    flags       *: culong
    filesize    *: libssh2_uint64_t
    uid         *: culong
    gid         *: culong
    permissions *: culong
    atime       *: culong
    mtime       *: culong

  _LIBSSH2_SFTP_STATVFS* {.incompleteStruct.} = object
    f_bsize   *: libssh2_uint64_t
    f_frsize  *: libssh2_uint64_t
    f_blocks  *: libssh2_uint64_t
    f_bfree   *: libssh2_uint64_t
    f_bavail  *: libssh2_uint64_t
    f_files   *: libssh2_uint64_t
    f_ffree   *: libssh2_uint64_t
    f_favail  *: libssh2_uint64_t
    f_fsid    *: libssh2_uint64_t
    f_flag    *: libssh2_uint64_t
    f_namemax *: libssh2_uint64_t

  LIBSSH2_SFTP_ATTRIBUTES* {.bycopy.} = object
    flags       *: culong
    filesize    *: libssh2_uint64_t
    uid         *: culong
    gid         *: culong
    permissions *: culong
    atime       *: culong
    mtime       *: culong

  LIBSSH2_SFTP_STATVFS* {.bycopy.} = object
    f_bsize   *: libssh2_uint64_t
    f_frsize  *: libssh2_uint64_t
    f_blocks  *: libssh2_uint64_t
    f_bfree   *: libssh2_uint64_t
    f_bavail  *: libssh2_uint64_t
    f_files   *: libssh2_uint64_t
    f_ffree   *: libssh2_uint64_t
    f_favail  *: libssh2_uint64_t
    f_fsid    *: libssh2_uint64_t
    f_flag    *: libssh2_uint64_t
    f_namemax *: libssh2_uint64_t

  LIBSSH2_SFTP* {.incompleteStruct.} = object


  LIBSSH2_SFTP_HANDLE* {.incompleteStruct.} = object




proc libssh2_sftp_init*(session: ptr LIBSSH2_SESSION): ptr LIBSSH2_SFTP {.importc: "libssh2_sftp_init".}

proc libssh2_sftp_shutdown*(sftp: ptr LIBSSH2_SFTP): cint {.importc: "libssh2_sftp_shutdown".}

proc libssh2_sftp_last_error*(sftp: ptr LIBSSH2_SFTP): culong {.importc: "libssh2_sftp_last_error".}

proc libssh2_sftp_get_channel*(sftp: ptr LIBSSH2_SFTP): ptr LIBSSH2_CHANNEL {.importc: "libssh2_sftp_get_channel".}

proc libssh2_sftp_open_ex*(
    sftp: ptr LIBSSH2_SFTP,
    filename: cstring,
    filename_len: cuint,
    flags: culong,
    mode: clong,
    open_type: cint,
): ptr LIBSSH2_SFTP_HANDLE {.importc: "libssh2_sftp_open_ex".}

proc libssh2_sftp_open_ex_r*(
    sftp: ptr LIBSSH2_SFTP,
    filename: cstring,
    filename_len: csize_t,
    flags: culong,
    mode: clong,
    open_type: cint,
    attrs: ptr LIBSSH2_SFTP_ATTRIBUTES,
): ptr LIBSSH2_SFTP_HANDLE {.importc: "libssh2_sftp_open_ex_r".}

proc libssh2_sftp_read*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    buffer: ptr char,
    buffer_maxlen: csize_t,
): csize_t {.importc: "libssh2_sftp_read".}

proc libssh2_sftp_readdir_ex*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    buffer: ptr char,
    buffer_maxlen: csize_t,
    longentry: ptr char,
    longentry_maxlen: csize_t,
    attrs: ptr LIBSSH2_SFTP_ATTRIBUTES,
): cint {.importc: "libssh2_sftp_readdir_ex".}

proc libssh2_sftp_write*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    buffer: cstring,
    count: csize_t,
): csize_t {.importc: "libssh2_sftp_write".}

proc libssh2_sftp_fsync*(handle: ptr LIBSSH2_SFTP_HANDLE): cint {.importc: "libssh2_sftp_fsync".}

proc libssh2_sftp_close_handle*(handle: ptr LIBSSH2_SFTP_HANDLE): cint {.importc: "libssh2_sftp_close_handle".}

proc libssh2_sftp_seek*(handle: ptr LIBSSH2_SFTP_HANDLE, offset: csize_t): void {.importc: "libssh2_sftp_seek".}

proc libssh2_sftp_seek64*(handle: ptr LIBSSH2_SFTP_HANDLE, offset: libssh2_uint64_t): void {.importc: "libssh2_sftp_seek64".}

proc libssh2_sftp_tell*(handle: ptr LIBSSH2_SFTP_HANDLE): csize_t {.importc: "libssh2_sftp_tell".}

proc libssh2_sftp_tell64*(handle: ptr LIBSSH2_SFTP_HANDLE): libssh2_uint64_t {.importc: "libssh2_sftp_tell64".}

proc libssh2_sftp_fstat_ex*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    attrs: ptr LIBSSH2_SFTP_ATTRIBUTES,
    setstat: cint,
): cint {.importc: "libssh2_sftp_fstat_ex".}

proc libssh2_sftp_rename_ex*(
    sftp: ptr LIBSSH2_SFTP,
    source_filename: cstring,
    srouce_filename_len: cuint,
    dest_filename: cstring,
    dest_filename_len: cuint,
    flags: clong,
): cint {.importc: "libssh2_sftp_rename_ex".}

proc libssh2_sftp_unlink_ex*(
    sftp: ptr LIBSSH2_SFTP,
    filename: cstring,
    filename_len: cuint,
): cint {.importc: "libssh2_sftp_unlink_ex".}

proc libssh2_sftp_fstatvfs*(handle: ptr LIBSSH2_SFTP_HANDLE, st: ptr LIBSSH2_SFTP_STATVFS): cint {.importc: "libssh2_sftp_fstatvfs".}

proc libssh2_sftp_statvfs*(
    sftp: ptr LIBSSH2_SFTP,
    path: cstring,
    path_len: csize_t,
    st: ptr LIBSSH2_SFTP_STATVFS,
): cint {.importc: "libssh2_sftp_statvfs".}

proc libssh2_sftp_mkdir_ex*(
    sftp: ptr LIBSSH2_SFTP,
    path: cstring,
    path_len: cuint,
    mode: clong,
): cint {.importc: "libssh2_sftp_mkdir_ex".}

proc libssh2_sftp_rmdir_ex*(
    sftp: ptr LIBSSH2_SFTP,
    path: cstring,
    path_len: cuint,
): cint {.importc: "libssh2_sftp_rmdir_ex".}

proc libssh2_sftp_stat_ex*(
    sftp: ptr LIBSSH2_SFTP,
    path: cstring,
    path_len: cuint,
    stat_type: cint,
    attrs: ptr LIBSSH2_SFTP_ATTRIBUTES,
): cint {.importc: "libssh2_sftp_stat_ex".}

proc libssh2_sftp_symlink_ex*(
    sftp: ptr LIBSSH2_SFTP,
    path: cstring,
    path_len: cuint,
    target: ptr char,
    target_len: cuint,
    link_type: cint,
): cint {.importc: "libssh2_sftp_symlink_ex".}