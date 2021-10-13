{.push warning[UnusedImport]:off.}

import
  ./libssh2,
  ./libssh2_config

type
  LIBSSH2_SFTP_ATTRIBUTES* {.bycopy, header: "<ssh2/libssh2_sftp.h>", importc.} = object
    ## Flags for open_ex() 
    ## Flags for rename_ex() 
    ## Flags for stat_ex() 
    ## Flags for symlink_ex() 
    ## Flags for sftp_mkdir() 
    ## SFTP attribute flag bits 
    ## SFTP statvfs flag bits 
    flags*: culong
    filesize*: libssh2_uint64_t
    gid*: culong
    permissions*: culong
    mtime*: culong
   
  LIBSSH2_SFTP_STATVFS* {.bycopy, header: "<ssh2/libssh2_sftp.h>", importc.} = object
    f_bsize*: libssh2_uint64_t
    f_frsize*: libssh2_uint64_t ## file system block size 
    f_blocks*: libssh2_uint64_t ## fragment size 
    f_bfree*: libssh2_uint64_t ## size of fs in f_frsize units 
    f_bavail*: libssh2_uint64_t ## # free blocks 
    f_files*: libssh2_uint64_t ## # free blocks for non-root 
    f_ffree*: libssh2_uint64_t ## # inodes 
    f_favail*: libssh2_uint64_t ## # free inodes 
    f_fsid*: libssh2_uint64_t ## # free inodes for non-root 
    f_flag*: libssh2_uint64_t ## file system ID 
    f_namemax*: libssh2_uint64_t ## mount flags 
   

proc libssh2_sftp_init*(
    session: ptr LIBSSH2_SESSION
  ): ptr LIBSSH2_SFTP {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_shutdown*(
    sftp: ptr LIBSSH2_SFTP
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_last_error*(
    sftp: ptr LIBSSH2_SFTP
  ): culong {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_get_channel*(
    sftp: ptr LIBSSH2_SFTP
  ): ptr LIBSSH2_CHANNEL {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_open_ex*(
    sftp:         ptr LIBSSH2_SFTP,
    filename:     cstring,
    filename_len: cuint,
    flags:        culong,
    mode:         clong,
    open_type:    cint
  ): ptr LIBSSH2_SFTP_HANDLE {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_read*(
    handle:        ptr LIBSSH2_SFTP_HANDLE,
    buffer:        cstring,
    buffer_maxlen: csize_t
  ): csize_t {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_readdir_ex*(
    handle:           ptr LIBSSH2_SFTP_HANDLE,
    buffer:           cstring,
    buffer_maxlen:    csize_t,
    longentry:        cstring,
    longentry_maxlen: csize_t,
    attrs:            ptr LIBSSH2_SFTP_ATTRIBUTES
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_write*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    buffer: cstring,
    count:  csize_t
  ): csize_t {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_fsync*(
    handle: ptr LIBSSH2_SFTP_HANDLE
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_close_handle*(
    handle: ptr LIBSSH2_SFTP_HANDLE
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_seek*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    offset: csize_t
  ): void {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_seek64*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    offset: libssh2_uint64_t
  ): void {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_tell*(
    handle: ptr LIBSSH2_SFTP_HANDLE
  ): csize_t {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_tell64*(
    handle: ptr LIBSSH2_SFTP_HANDLE
  ): libssh2_uint64_t {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_fstat_ex*(
    handle:  ptr LIBSSH2_SFTP_HANDLE,
    attrs:   ptr LIBSSH2_SFTP_ATTRIBUTES,
    setstat: cint
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_rename_ex*(
    sftp:                ptr LIBSSH2_SFTP,
    source_filename:     cstring,
    srouce_filename_len: cuint,
    dest_filename:       cstring,
    dest_filename_len:   cuint,
    flags:               clong
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_unlink_ex*(
    sftp:         ptr LIBSSH2_SFTP,
    filename:     cstring,
    filename_len: cuint
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_fstatvfs*(
    handle: ptr LIBSSH2_SFTP_HANDLE,
    st:     ptr LIBSSH2_SFTP_STATVFS
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_statvfs*(
    sftp:     ptr LIBSSH2_SFTP,
    path:     cstring,
    path_len: csize_t,
    st:       ptr LIBSSH2_SFTP_STATVFS
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_mkdir_ex*(
    sftp:     ptr LIBSSH2_SFTP,
    path:     cstring,
    path_len: cuint,
    mode:     clong
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_rmdir_ex*(
    sftp:     ptr LIBSSH2_SFTP,
    path:     cstring,
    path_len: cuint
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_stat_ex*(
    sftp:      ptr LIBSSH2_SFTP,
    path:      cstring,
    path_len:  cuint,
    stat_type: cint,
    attrs:     ptr LIBSSH2_SFTP_ATTRIBUTES
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_sftp_symlink_ex*(
    sftp:       ptr LIBSSH2_SFTP,
    path:       cstring,
    path_len:   cuint,
    target:     cstring,
    target_len: cuint,
    link_type:  cint
  ): cint {.dynlib: libssh2Dl, importc.}


