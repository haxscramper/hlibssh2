{.push warning[UnusedImport]:off.}

import
  ./libssh2,
  ./libssh2_config

type
  LIBSSH2_PUBLICKEY1* = LIBSSH2_PUBLICKEY
   
  libssh2_publickey_attribute* {.bycopy, header: "<ssh2/libssh2_publickey.h>",
                                 importc.} = object
    name*:      cstring
    name_len*:  culong 
    value*:     cstring
    value_len*: culong 
    mandatory*: char   
   
  libssh2_publickey_attribute1* = libssh2_publickey_attribute
   
  libssh2_publickey_list* {.bycopy, header: "<ssh2/libssh2_publickey.h>", importc.} = object
    packet*:    ptr uint8                                       
    name*:      ptr uint8                        ## For freeing 
    name_len*:  culong                                          
    blob*:      ptr uint8                                       
    blob_len*:  culong                                          
    num_attrs*: culong                                          
    attrs*:     ptr libssh2_publickey_attribute1 ## free me     
   
  libssh2_publickey_list1* = libssh2_publickey_list
   

proc libssh2_publickey_init*(
    session: ptr LIBSSH2_SESSION
  ): ptr LIBSSH2_PUBLICKEY1 {.ssh2Proc, importc.}
  
 

proc libssh2_publickey_add_ex*(
    pkey:      ptr LIBSSH2_PUBLICKEY1,
    name:      ptr uint8,
    name_len:  culong,
    blob:      ptr uint8,
    blob_len:  culong,
    overwrite: char,
    num_attrs: culong,
    attrs:     ptr UncheckedArray[libssh2_publickey_attribute1]
  ): cint {.ssh2Proc, importc.}
  
 

proc libssh2_publickey_remove_ex*(
    pkey:     ptr LIBSSH2_PUBLICKEY1,
    name:     ptr uint8,
    name_len: culong,
    blob:     ptr uint8,
    blob_len: culong
  ): cint {.ssh2Proc, importc.}
  
 

proc libssh2_publickey_list_fetch*(
    pkey:      ptr LIBSSH2_PUBLICKEY1,
    num_keys:  ptr culong,
    pkey_list: ptr ptr libssh2_publickey_list1
  ): cint {.ssh2Proc, importc.}
  
 

proc libssh2_publickey_list_free*(
    pkey:      ptr LIBSSH2_PUBLICKEY1,
    pkey_list: ptr libssh2_publickey_list1
  ): void {.ssh2Proc, importc.}
  
 

proc libssh2_publickey_shutdown*(
    pkey: ptr LIBSSH2_PUBLICKEY1
  ): cint {.ssh2Proc, importc.}
  
 

