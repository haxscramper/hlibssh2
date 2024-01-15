import "./libssh2_config.nim" ## From gen file
import "./libssh2.nim"

type
  LIBSSH2_PUBLICKEY* {.incompleteStruct.} = object


  libssh2_publickey_attribute* {.bycopy.} = object
    name      *: cstring
    name_len  *: culong
    value     *: cstring
    value_len *: culong
    mandatory *: char

  libssh2_publickey_list* {.bycopy.} = object
    packet    *: ptr char
    name      *: cstring
    name_len  *: culong
    blob      *: cstring
    blob_len  *: culong
    num_attrs *: culong
    attrs     *: ptr libssh2_publickey_attribute



proc libssh2_publickey_add_ex*(
    pkey: ptr LIBSSH2_PUBLICKEY,
    name: cstring,
    name_len: culong,
    blob: cstring,
    blob_len: culong,
    overwrite: char,
    num_attrs: culong,
    attrs: ptr libssh2_publickey_attribute,
): cint {.importc: "libssh2_publickey_add_ex".}

proc libssh2_publickey_remove_ex*(
    pkey: ptr LIBSSH2_PUBLICKEY,
    name: cstring,
    name_len: culong,
    blob: cstring,
    blob_len: culong,
): cint {.importc: "libssh2_publickey_remove_ex".}

proc libssh2_publickey_list_fetch*(
    pkey: ptr LIBSSH2_PUBLICKEY,
    num_keys: ptr culong,
    pkey_list: ptr ptr libssh2_publickey_list,
): cint {.importc: "libssh2_publickey_list_fetch".}

proc libssh2_publickey_list_free*(pkey: ptr LIBSSH2_PUBLICKEY, pkey_list: ptr libssh2_publickey_list): void {.importc: "libssh2_publickey_list_free".}

proc libssh2_publickey_shutdown*(pkey: ptr LIBSSH2_PUBLICKEY): cint {.importc: "libssh2_publickey_shutdown".}

proc libssh2_publickey_init*(session: ptr LIBSSH2_SESSION): ptr LIBSSH2_PUBLICKEY {.importc: "libssh2_publickey_init".}