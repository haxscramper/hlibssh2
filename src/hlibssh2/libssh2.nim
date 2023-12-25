{.push warning[UnusedImport]:off.}

import
  ./libssh2_config

type
  LIBSSH2_AGENT* {.bycopy, incompleteStruct, header: "<ssh2/libssh2.h>", importc.} = object


  LIBSSH2_AGENT1* = LIBSSH2_AGENT

  LIBSSH2_CHANNEL* {.bycopy, incompleteStruct, header: "<ssh2/libssh2.h>", importc.} = object


  LIBSSH2_CHANNEL1* = LIBSSH2_CHANNEL

  LIBSSH2_KNOWNHOSTS* {.bycopy, incompleteStruct, header: "<ssh2/libssh2.h>", importc.} = object


  LIBSSH2_KNOWNHOSTS1* = LIBSSH2_KNOWNHOSTS

  LIBSSH2_LISTENER* {.bycopy, incompleteStruct, header: "<ssh2/libssh2.h>", importc.} = object


  LIBSSH2_LISTENER1* = LIBSSH2_LISTENER

  LIBSSH2_POLLFD* {.bycopy, union, header: "<ssh2/libssh2.h>", importc.} = object
    type_f* {.importc: "type".}: uint8
    fd*:                         LIBSSH2_POLLFDfd
    events*:                     uint32
    revents*:                    uint32

  LIBSSH2_POLLFD1* = LIBSSH2_POLLFD

  LIBSSH2_POLLFDfd* {.bycopy, union, importc.} = object
    socket*:   libssh2_socket_t
    channel*:  ptr LIBSSH2_CHANNEL1
    listener*: ptr LIBSSH2_LISTENER1

  LIBSSH2_SESSION* {.bycopy, incompleteStruct, header: "<ssh2/libssh2.h>", importc.} = object


  LIBSSH2_SESSION1* = LIBSSH2_SESSION

  LIBSSH2_USERAUTH_KBDINT_PROMPT* {.bycopy, union, header: "<ssh2/libssh2.h>", importc.} = object
    text*:   cstring
    length*: cuint
    echo*:   uint8

  LIBSSH2_USERAUTH_KBDINT_PROMPT1* = LIBSSH2_USERAUTH_KBDINT_PROMPT

  LIBSSH2_USERAUTH_KBDINT_RESPONSE* {.bycopy, union, header: "<ssh2/libssh2.h>", importc.} = object
    text*:   cstring
    length*: cuint

  LIBSSH2_USERAUTH_KBDINT_RESPONSE1* = LIBSSH2_USERAUTH_KBDINT_RESPONSE

  libssh2_agent_publickey* {.bycopy, union, header: "<ssh2/libssh2.h>", importc.} = object
    magic*:    cuint
    node*:     pointer
    blob*:     ptr uint8
    blob_len*: csize_t
    comment*:  cstring

  libssh2_int64_t* = int64

  libssh2_knownhost* {.bycopy, union, header: "<ssh2/libssh2.h>", importc.} = object
    magic*:    cuint
    node*:     pointer
    name*:     cstring
    key*:      cstring
    typemask*: cint

  libssh2_socket_t* = cint

  libssh2_struct_stat* = stat

  libssh2_struct_stat_size* = int32

  libssh2_trace_handler_func* = ptr proc(arg0: ptr LIBSSH2_SESSION,
                                         arg1: pointer,
                                         arg2: cstring,
                                         arg3: uint32): void{.cdecl.}

  libssh2_uint64_t* = uint64


proc libssh2_init*(flags: cint): cint {.ssh2Proc, importc.}



proc libssh2_exit*(): void {.ssh2Proc, importc.}



proc libssh2_free*(
    session: ptr LIBSSH2_SESSION1,
    arg_ptr: pointer
  ): void {.ssh2Proc, importc.}



proc libssh2_session_supported_algs*(
    session:     ptr LIBSSH2_SESSION1,
    method_type: cint,
    algs:        ptr ptr cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_init_ex*(
    my_alloc:   ptr proc (arg0: csize_t; arg1: ptr pointer): pointer {.cdecl.},
    my_free:    ptr proc (arg0: pointer; arg1: ptr pointer): void {.cdecl.},
    my_realloc: ptr proc (arg0: pointer; arg1: csize_t; arg2: ptr pointer): pointer {.cdecl.},
    abstract:   pointer
  ): ptr LIBSSH2_SESSION1 {.ssh2Proc, importc.}



proc libssh2_session_abstract*(
    session: ptr LIBSSH2_SESSION1
  ): ptr pointer {.ssh2Proc, importc.}



proc libssh2_session_callback_set*(
    session:  ptr LIBSSH2_SESSION1,
    cbtype:   cint,
    callback: pointer
  ): pointer {.ssh2Proc, importc.}



proc libssh2_session_banner_set*(
    session: ptr LIBSSH2_SESSION1,
    banner:  cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_banner_set*(
    session: ptr LIBSSH2_SESSION1,
    banner:  cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_startup*(
    session: ptr LIBSSH2_SESSION1,
    sock:    cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_handshake*(
    session: ptr LIBSSH2_SESSION1,
    sock:    libssh2_socket_t
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_disconnect_ex*(
    session:     ptr LIBSSH2_SESSION1,
    reason:      cint,
    description: cstring,
    lang:        cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_free*(
    session: ptr LIBSSH2_SESSION1
  ): cint {.ssh2Proc, importc.}



proc libssh2_hostkey_hash*(
    session:   ptr LIBSSH2_SESSION1,
    hash_type: cint
  ): cstring {.ssh2Proc, importc.}



proc libssh2_session_hostkey*(
    session: ptr LIBSSH2_SESSION1,
    len:     ptr csize_t,
    type_f:  ptr cint
  ): cstring {.ssh2Proc, importc.}



proc libssh2_session_method_pref*(
    session:     ptr LIBSSH2_SESSION1,
    method_type: cint,
    prefs:       cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_methods*(
    session:     ptr LIBSSH2_SESSION1,
    method_type: cint
  ): cstring {.ssh2Proc, importc.}



proc libssh2_session_last_error*(
    session:    ptr LIBSSH2_SESSION1,
    errmsg:     ptr cstring,
    errmsg_len: ptr cint,
    want_buf:   cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_last_errno*(
    session: ptr LIBSSH2_SESSION1
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_set_last_error*(
    session: ptr LIBSSH2_SESSION1,
    errcode: cint,
    errmsg:  cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_block_directions*(
    session: ptr LIBSSH2_SESSION1
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_flag*(
    session: ptr LIBSSH2_SESSION1,
    flag:    cint,
    value:   cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_session_banner_get*(
    session: ptr LIBSSH2_SESSION1
  ): cstring {.ssh2Proc, importc.}



proc libssh2_userauth_list*(
    session:      ptr LIBSSH2_SESSION1,
    username:     cstring,
    username_len: cuint
  ): cstring {.ssh2Proc, importc.}



proc libssh2_userauth_authenticated*(
    session: ptr LIBSSH2_SESSION1
  ): cint {.ssh2Proc, importc.}



proc libssh2_userauth_password_ex*(
    session:          ptr LIBSSH2_SESSION1,
    username:         cstring,
    username_len:     cuint,
    password:         cstring,
    password_len:     cuint,
    passwd_change_cb: ptr proc (arg0: ptr LIBSSH2_SESSION1; arg1: ptr cstring; arg2: ptr cint;
                                arg3: ptr pointer): void {.cdecl.}
  ): cint {.ssh2Proc, importc.}



proc libssh2_userauth_publickey_fromfile_ex*(
    session:      ptr LIBSSH2_SESSION1,
    username:     cstring,
    username_len: cuint,
    publickey:    cstring,
    privatekey:   cstring,
    passphrase:   cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_userauth_publickey*(
    session:        ptr LIBSSH2_SESSION1,
    username:       cstring,
    pubkeydata:     ptr uint8,
    pubkeydata_len: csize_t,
    sign_callback:  ptr proc (arg0: ptr LIBSSH2_SESSION1; arg1: ptr ptr uint8; arg2: ptr csize_t;
                              arg3: ptr uint8; arg4: csize_t; arg5: ptr pointer): cint {.cdecl.},
    abstract:       ptr pointer
  ): cint {.ssh2Proc, importc.}



proc libssh2_userauth_hostbased_fromfile_ex*(
    session:            ptr LIBSSH2_SESSION1,
    username:           cstring,
    username_len:       cuint,
    publickey:          cstring,
    privatekey:         cstring,
    passphrase:         cstring,
    hostname:           cstring,
    hostname_len:       cuint,
    local_username:     cstring,
    local_username_len: cuint
  ): cint {.ssh2Proc, importc.}



proc libssh2_userauth_publickey_frommemory*(
    session:                ptr LIBSSH2_SESSION1,
    username:               cstring,
    username_len:           csize_t,
    publickeyfiledata:      cstring,
    publickeyfiledata_len:  csize_t,
    privatekeyfiledata:     cstring,
    privatekeyfiledata_len: csize_t,
    passphrase:             cstring
  ): cint {.ssh2Proc, importc.}



proc libssh2_userauth_keyboard_interactive_ex*(
    session:           ptr LIBSSH2_SESSION1,
    username:          cstring,
    username_len:      cuint,
    response_callback: ptr proc (arg0: cstring; arg1: cint; arg2: cstring; arg3: cint; arg4: cint;
                                 arg5: ptr LIBSSH2_USERAUTH_KBDINT_PROMPT1;
                                 arg6: ptr LIBSSH2_USERAUTH_KBDINT_RESPONSE1; arg7: ptr pointer): void {.
                           cdecl.}
  ): cint {.ssh2Proc, importc.}



proc libssh2_poll*(
    fds:     ptr LIBSSH2_POLLFD1,
    nfds:    cuint,
    timeout: int32
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_open_ex*(
    session:          ptr LIBSSH2_SESSION1,
    channel_type:     cstring,
    channel_type_len: cuint,
    window_size:      cuint,
    packet_size:      cuint,
    message:          cstring,
    message_len:      cuint
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_channel_direct_tcpip_ex*(
    session: ptr LIBSSH2_SESSION1,
    host:    cstring,
    port:    cint,
    shost:   cstring,
    sport:   cint
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_channel_forward_listen_ex*(
    session:       ptr LIBSSH2_SESSION1,
    host:          cstring,
    port:          cint,
    bound_port:    ptr cint,
    queue_maxsize: cint
  ): ptr LIBSSH2_LISTENER1 {.ssh2Proc, importc.}



proc libssh2_channel_forward_cancel*(
    listener: ptr LIBSSH2_LISTENER1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_forward_accept*(
    listener: ptr LIBSSH2_LISTENER1
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_channel_setenv_ex*(
    channel:     ptr LIBSSH2_CHANNEL1,
    varname:     cstring,
    varname_len: cuint,
    value:       cstring,
    value_len:   cuint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_request_auth_agent*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_request_pty_ex*(
    channel:   ptr LIBSSH2_CHANNEL1,
    term:      cstring,
    term_len:  cuint,
    modes:     cstring,
    modes_len: cuint,
    width:     cint,
    height:    cint,
    width_px:  cint,
    height_px: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_request_pty_size_ex*(
    channel:   ptr LIBSSH2_CHANNEL1,
    width:     cint,
    height:    cint,
    width_px:  cint,
    height_px: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_x11_req_ex*(
    channel:           ptr LIBSSH2_CHANNEL1,
    single_connection: cint,
    auth_proto:        cstring,
    auth_cookie:       cstring,
    screen_number:     cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_process_startup*(
    channel:     ptr LIBSSH2_CHANNEL1,
    request:     cstring,
    request_len: cuint,
    message:     cstring,
    message_len: cuint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_read_ex*(
    channel:   ptr LIBSSH2_CHANNEL1,
    stream_id: cint,
    buf:       cstring,
    buflen:    csize_t
  ): csize_t {.ssh2Proc, importc.}



proc libssh2_poll_channel_read*(
    channel:  ptr LIBSSH2_CHANNEL1,
    extended: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_window_read_ex*(
    channel:             ptr LIBSSH2_CHANNEL1,
    read_avail:          ptr uint32,
    window_size_initial: ptr uint32
  ): uint32 {.ssh2Proc, importc.}



proc libssh2_channel_receive_window_adjust*(
    channel:    ptr LIBSSH2_CHANNEL1,
    adjustment: uint32,
    force:      uint8
  ): uint32 {.ssh2Proc, importc.}



proc libssh2_channel_receive_window_adjust2*(
    channel:     ptr LIBSSH2_CHANNEL1,
    adjustment:  uint32,
    force:       uint8,
    storewindow: ptr cuint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_write_ex*(
    channel:   ptr LIBSSH2_CHANNEL1,
    stream_id: cint,
    buf:       cstring,
    buflen:    csize_t
  ): csize_t {.ssh2Proc, importc.}



proc libssh2_channel_window_write_ex*(
    channel:             ptr LIBSSH2_CHANNEL1,
    window_size_initial: ptr uint32
  ): uint32 {.ssh2Proc, importc.}



proc libssh2_session_set_blocking*(
    session:  ptr LIBSSH2_SESSION1,
    blocking: cint
  ): void {.ssh2Proc, importc.}



proc libssh2_session_get_blocking*(
    session: ptr LIBSSH2_SESSION1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_set_blocking*(
    channel:  ptr LIBSSH2_CHANNEL1,
    blocking: cint
  ): void {.ssh2Proc, importc.}



proc libssh2_session_set_timeout*(
    session: ptr LIBSSH2_SESSION1,
    timeout: int32
  ): void {.ssh2Proc, importc.}



proc libssh2_session_get_timeout*(
    session: ptr LIBSSH2_SESSION1
  ): int32 {.ssh2Proc, importc.}



proc libssh2_channel_handle_extended_data*(
    channel:     ptr LIBSSH2_CHANNEL1,
    ignore_mode: cint
  ): void {.ssh2Proc, importc.}



proc libssh2_channel_handle_extended_data2*(
    channel:     ptr LIBSSH2_CHANNEL1,
    ignore_mode: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_flush_ex*(
    channel:   ptr LIBSSH2_CHANNEL1,
    streamid1: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_get_exit_status*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_get_exit_signal*(
    channel:        ptr LIBSSH2_CHANNEL1,
    exitsignal:     ptr cstring,
    exitsignal_len: ptr csize_t,
    errmsg:         ptr cstring,
    errmsg_len:     ptr csize_t,
    langtag:        ptr cstring,
    langtag_len:    ptr csize_t
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_send_eof*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_eof*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_wait_eof*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_close*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_wait_closed*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_channel_free*(
    channel: ptr LIBSSH2_CHANNEL1
  ): cint {.ssh2Proc, importc.}



proc libssh2_scp_recv*(
    session: ptr LIBSSH2_SESSION1,
    path:    cstring,
    sb:      ptr stat
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_scp_recv2*(
    session: ptr LIBSSH2_SESSION1,
    path:    cstring,
    sb:      ptr libssh2_struct_stat
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_scp_send_ex*(
    session: ptr LIBSSH2_SESSION1,
    path:    cstring,
    mode:    cint,
    size:    csize_t,
    mtime:   int32,
    atime:   int32
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_scp_send64*(
    session: ptr LIBSSH2_SESSION1,
    path:    cstring,
    mode:    cint,
    size:    libssh2_int64_t,
    mtime:   time_t,
    atime:   time_t
  ): ptr LIBSSH2_CHANNEL1 {.ssh2Proc, importc.}



proc libssh2_base64_decode*(
    session:  ptr LIBSSH2_SESSION1,
    dest:     ptr cstring,
    dest_len: ptr cuint,
    src:      cstring,
    src_len:  cuint
  ): cint {.ssh2Proc, importc.}



proc libssh2_version*(req_version_num: cint): cstring {.ssh2Proc, importc.}



proc libssh2_knownhost_init*(
    session: ptr LIBSSH2_SESSION1
  ): ptr LIBSSH2_KNOWNHOSTS1 {.ssh2Proc, importc.}



proc libssh2_knownhost_add*(
    hosts:    ptr LIBSSH2_KNOWNHOSTS1,
    host:     cstring,
    salt:     cstring,
    key:      cstring,
    keylen:   csize_t,
    typemask: cint,
    store:    ptr ptr libssh2_knownhost
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_addc*(
    hosts:      ptr LIBSSH2_KNOWNHOSTS1,
    host:       cstring,
    salt:       cstring,
    key:        cstring,
    keylen:     csize_t,
    comment:    cstring,
    commentlen: csize_t,
    typemask:   cint,
    store:      ptr ptr libssh2_knownhost
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_check*(
    hosts:     ptr LIBSSH2_KNOWNHOSTS1,
    host:      cstring,
    key:       cstring,
    keylen:    csize_t,
    typemask:  cint,
    knownhost: ptr ptr libssh2_knownhost
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_checkp*(
    hosts:     ptr LIBSSH2_KNOWNHOSTS1,
    host:      cstring,
    port:      cint,
    key:       cstring,
    keylen:    csize_t,
    typemask:  cint,
    knownhost: ptr ptr libssh2_knownhost
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_del*(
    hosts: ptr LIBSSH2_KNOWNHOSTS1,
    entry: ptr libssh2_knownhost
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_free*(
    hosts: ptr LIBSSH2_KNOWNHOSTS1
  ): void {.ssh2Proc, importc.}



proc libssh2_knownhost_readline*(
    hosts:  ptr LIBSSH2_KNOWNHOSTS1,
    line:   cstring,
    len:    csize_t,
    type_f: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_readfile*(
    hosts:    ptr LIBSSH2_KNOWNHOSTS1,
    filename: cstring,
    type_f:   cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_writeline*(
    hosts:  ptr LIBSSH2_KNOWNHOSTS1,
    known:  ptr libssh2_knownhost,
    buffer: cstring,
    buflen: csize_t,
    outlen: ptr csize_t,
    type_f: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_writefile*(
    hosts:    ptr LIBSSH2_KNOWNHOSTS1,
    filename: cstring,
    type_f:   cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_knownhost_get*(
    hosts: ptr LIBSSH2_KNOWNHOSTS1,
    store: ptr ptr libssh2_knownhost,
    prev:  ptr libssh2_knownhost
  ): cint {.ssh2Proc, importc.}



proc libssh2_agent_init*(
    session: ptr LIBSSH2_SESSION1
  ): ptr LIBSSH2_AGENT1 {.ssh2Proc, importc.}



proc libssh2_agent_connect*(
    agent: ptr LIBSSH2_AGENT1
  ): cint {.ssh2Proc, importc.}



proc libssh2_agent_list_identities*(
    agent: ptr LIBSSH2_AGENT1
  ): cint {.ssh2Proc, importc.}



proc libssh2_agent_get_identity*(
    agent: ptr LIBSSH2_AGENT1,
    store: ptr ptr libssh2_agent_publickey,
    prev:  ptr libssh2_agent_publickey
  ): cint {.ssh2Proc, importc.}



proc libssh2_agent_userauth*(
    agent:    ptr LIBSSH2_AGENT1,
    username: cstring,
    identity: ptr libssh2_agent_publickey
  ): cint {.ssh2Proc, importc.}



proc libssh2_agent_disconnect*(
    agent: ptr LIBSSH2_AGENT1
  ): cint {.ssh2Proc, importc.}



proc libssh2_agent_free*(agent: ptr LIBSSH2_AGENT1): void {.ssh2Proc, importc.}



proc libssh2_agent_set_identity_path*(
    agent: ptr LIBSSH2_AGENT1,
    path:  cstring
  ): void {.ssh2Proc, importc.}



proc libssh2_agent_get_identity_path*(
    agent: ptr LIBSSH2_AGENT1
  ): cstring {.ssh2Proc, importc.}



proc libssh2_keepalive_config*(
    session:    ptr LIBSSH2_SESSION1,
    want_reply: cint,
    interval:   cuint
  ): void {.ssh2Proc, importc.}



proc libssh2_keepalive_send*(
    session:         ptr LIBSSH2_SESSION1,
    seconds_to_next: ptr cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_trace*(
    session: ptr LIBSSH2_SESSION1,
    bitmask: cint
  ): cint {.ssh2Proc, importc.}



proc libssh2_trace_sethandler*(
    session:  ptr LIBSSH2_SESSION1,
    context:  pointer,
    callback: libssh2_trace_handler_func
  ): cint {.ssh2Proc, importc.}



