{.push warning[UnusedImport]:off.}

import
  ./libssh2,
  ./libssh2_config

type
  LIBSSH2_PUBLICKEY* {.bycopy, incompleteStruct, header: "<ssh2/libssh2_publickey.h>", importc.} = object


  LIBSSH2_PUBLICKEY1* = LIBSSH2_PUBLICKEY

  libssh2_publickey_attribute* = libssh2_publickey_attribute1

  libssh2_publickey_attribute1* {.bycopy, union, header: "<ssh2/libssh2_publickey.h>", importc.} = object
    name*:      cstring
    name_len*:  uint32
    value*:     cstring
    value_len*: uint32
    mandatory*: char

  libssh2_publickey_list* {.bycopy, union, header: "<ssh2/libssh2_publickey.h>", importc.} = object
    packet*:    ptr uint8
    name*:      ptr uint8
    name_len*:  uint32
    blob*:      ptr uint8
    blob_len*:  uint32
    num_attrs*: uint32
    attrs*:     ptr libssh2_publickey_attribute

  libssh2_publickey_list1* = libssh2_publickey_list


proc libssh2_publickey_init*(
    session: ptr LIBSSH2_SESSION
  ): ptr LIBSSH2_PUBLICKEY1 {.ssh2Proc, importc.}



proc libssh2_publickey_add_ex*(
    pkey:      ptr LIBSSH2_PUBLICKEY1,
    name:      ptr uint8,
    name_len:  uint32,
    blob:      ptr uint8,
    blob_len:  uint32,
    overwrite: char,
    num_attrs: uint32,
    attrs:     ptr UncheckedArray[libssh2_publickey_attribute]
  ): cint {.ssh2Proc, importc.}



proc libssh2_publickey_remove_ex*(
    pkey:     ptr LIBSSH2_PUBLICKEY1,
    name:     ptr uint8,
    name_len: uint32,
    blob:     ptr uint8,
    blob_len: uint32
  ): cint {.ssh2Proc, importc.}



proc libssh2_publickey_list_fetch*(
    pkey:      ptr LIBSSH2_PUBLICKEY1,
    num_keys:  ptr uint32,
    pkey_list: ptr ptr libssh2_publickey_list1
  ): cint {.ssh2Proc, importc.}



proc libssh2_publickey_list_free*(
    pkey:      ptr LIBSSH2_PUBLICKEY1,
    pkey_list: ptr libssh2_publickey_list1
  ): void {.ssh2Proc, importc.}



proc libssh2_publickey_shutdown*(
    pkey: ptr LIBSSH2_PUBLICKEY1
  ): cint {.ssh2Proc, importc.}



