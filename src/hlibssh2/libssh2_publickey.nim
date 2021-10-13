{.push warning[UnusedImport]:off.}

import
  ./libssh2,
  ./libssh2_config

type
  libssh2_publickey_attribute* {.bycopy, header: "<ssh2/libssh2_publickey.h>",
                                 importc.} = object
    name*: cstring
    name_len*: culong
    value*: cstring
    value_len*: culong
    mandatory*: char
   
  libssh2_publickey_list* {.bycopy, header: "<ssh2/libssh2_publickey.h>", importc.} = object
    packet*: ptr uint8
    name*: ptr uint8 ## For freeing 
    name_len*: culong
    blob*: ptr uint8
    blob_len*: culong
    num_attrs*: culong
    attrs*: ptr libssh2_publickey_attribute
   

proc libssh2_publickey_init*(
    session: ptr LIBSSH2_SESSION
  ): ptr LIBSSH2_PUBLICKEY {.dynlib: libssh2Dl, importc.}


proc libssh2_publickey_add_ex*(
    pkey:      ptr LIBSSH2_PUBLICKEY,
    name:      ptr uint8,
    name_len:  culong,
    blob:      ptr uint8,
    blob_len:  culong,
    overwrite: char,
    num_attrs: culong,
    attrs:     ptr UncheckedArray[libssh2_publickey_attribute]
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_publickey_remove_ex*(
    pkey:     ptr LIBSSH2_PUBLICKEY,
    name:     ptr uint8,
    name_len: culong,
    blob:     ptr uint8,
    blob_len: culong
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_publickey_list_fetch*(
    pkey:      ptr LIBSSH2_PUBLICKEY,
    num_keys:  ptr culong,
    pkey_list: ptr ptr libssh2_publickey_list
  ): cint {.dynlib: libssh2Dl, importc.}


proc libssh2_publickey_list_free*(
    pkey:      ptr LIBSSH2_PUBLICKEY,
    pkey_list: ptr libssh2_publickey_list
  ): void {.dynlib: libssh2Dl, importc.}


proc libssh2_publickey_shutdown*(
    pkey: ptr LIBSSH2_PUBLICKEY
  ): cint {.dynlib: libssh2Dl, importc.}


