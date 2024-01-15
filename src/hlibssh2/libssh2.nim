import "./libssh2_config.nim" ## From gen file

type
  LIBSSH2_USERAUTH_KBDINT_PROMPT* {.bycopy.} = object
    text   *: ptr char
    length *: csize_t
    echo   *: char

  LIBSSH2_USERAUTH_KBDINT_RESPONSE* {.bycopy.} = object
    text   *: ptr char
    length *: cuint

  LIBSSH2_SK_SIG_INFO* {.bycopy.} = object
    flags     *: uint8
    counter   *: uint32
    sig_r     *: ptr char
    sig_r_len *: csize_t
    sig_s     *: ptr char
    sig_s_len *: csize_t

  LIBSSH2_SESSION* {.incompleteStruct.} = object


  LIBSSH2_CHANNEL* {.incompleteStruct.} = object


  LIBSSH2_LISTENER* {.incompleteStruct.} = object


  LIBSSH2_KNOWNHOSTS* {.incompleteStruct.} = object


  LIBSSH2_AGENT* {.incompleteStruct.} = object


  LIBSSH2_PRIVKEY_SK* {.bycopy.} = object
    algorithm     *: cint
    flags         *: uint8
    application   *: cstring
    key_handle    *: cstring
    handle_len    *: csize_t
    sign_callback *: proc (a0: ptr LIBSSH2_SESSION, a1: ptr LIBSSH2_SK_SIG_INFO, a2: cstring, a3: csize_t, a4: cint, a5: uint8, a6: cstring, a7: cstring, a8: csize_t, a9: ptr pointer): cint
    orig_abstract *: ptr pointer

  LIBSSH2_POLLFD* {.bycopy.} = object
    `type`  *: char
    fd      *: LIBSSH2_POLLFD_fd_field
    events  *: culong
    revents *: culong

  LIBSSH2_POLLFD_fd_field* {.bycopy.} = object
    socket   *: libssh2_socket_t
    channel  *: ptr LIBSSH2_CHANNEL
    listener *: ptr LIBSSH2_LISTENER

  libssh2_knownhost* {.bycopy.} = object
    magic    *: cuint
    node     *: pointer
    name     *: ptr char
    key      *: ptr char
    typemask *: cint

  libssh2_agent_publickey* {.bycopy.} = object
    magic    *: cuint
    node     *: pointer
    blob     *: ptr char
    blob_len *: csize_t
    comment  *: ptr char

  c_libssh2_crypto_engine_t* {.size: sizeof(cint).} = enum
    c_libssh2_no_crypto = 0
    c_libssh2_openssl   = 1
    c_libssh2_gcrypt    = 2
    c_libssh2_mbedtls   = 3
    c_libssh2_wincng    = 4
    c_libssh2_os400qc3  = 5

  libssh2_crypto_engine_t* = enum
    libssh2_no_crypto = 0
    libssh2_openssl   = 1
    libssh2_gcrypt    = 2
    libssh2_mbedtls   = 3
    libssh2_wincng    = 4
    libssh2_os400qc3  = 5

  libssh2_uint64_t* = culonglong

  libssh2_int64_t* = clonglong

  libssh2_socket_t* = cint

  libssh2_struct_stat_size* = off_t

  libssh2_cb_generic* = proc (): void

  libssh2_trace_handler_func* = proc (a0: ptr LIBSSH2_SESSION, a1: pointer, a2: cstring, a3: csize_t): void



converter to_libssh2_crypto_engine_t*(arg: c_libssh2_crypto_engine_t): libssh2_crypto_engine_t =
  case arg:
    of c_libssh2_no_crypto: libssh2_no_crypto
    of c_libssh2_openssl  : libssh2_openssl
    of c_libssh2_gcrypt   : libssh2_gcrypt
    of c_libssh2_mbedtls  : libssh2_mbedtls
    of c_libssh2_wincng   : libssh2_wincng
    of c_libssh2_os400qc3 : libssh2_os400qc3

proc to_c_libssh2_crypto_engine_t*(arg: libssh2_crypto_engine_t): c_libssh2_crypto_engine_t =
  case arg:
    of libssh2_no_crypto: c_libssh2_no_crypto
    of libssh2_openssl  : c_libssh2_openssl
    of libssh2_gcrypt   : c_libssh2_gcrypt
    of libssh2_mbedtls  : c_libssh2_mbedtls
    of libssh2_wincng   : c_libssh2_wincng
    of libssh2_os400qc3 : c_libssh2_os400qc3

converter toCInt*(arg: c_libssh2_crypto_engine_t): cint = cint(ord(arg))

converter toCInt*(arg: libssh2_crypto_engine_t): cint = cint(ord(to_c_libssh2_crypto_engine_t(arg)))

converter toCInt*(args: set[libssh2_crypto_engine_t]): cint =
  for value in items(args):
    case value:
      of libssh2_no_crypto: result = cint(result or 0)
      of libssh2_openssl  : result = cint(result or 1)
      of libssh2_gcrypt   : result = cint(result or 2)
      of libssh2_mbedtls  : result = cint(result or 3)
      of libssh2_wincng   : result = cint(result or 4)
      of libssh2_os400qc3 : result = cint(result or 5)

func `-`*(arg: c_libssh2_crypto_engine_t, offset: int): cint = cast[c_libssh2_crypto_engine_t](ord(arg) - offset)

func `-`*(offset: int, arg: c_libssh2_crypto_engine_t): cint = cast[c_libssh2_crypto_engine_t](ord(arg) - offset)

func `+`*(arg: c_libssh2_crypto_engine_t, offset: int): cint = cast[c_libssh2_crypto_engine_t](ord(arg) + offset)

func `+`*(offset: int, arg: c_libssh2_crypto_engine_t): cint = cast[c_libssh2_crypto_engine_t](ord(arg) + offset)

proc libssh2_sign_sk*(
    session: ptr LIBSSH2_SESSION,
    sig: cstringArray,
    sig_len: ptr csize_t,
    data: cstring,
    data_len: csize_t,
    abstract: ptr pointer,
): cint {.importc: "libssh2_sign_sk".}

proc libssh2_init*(flags: cint): cint {.importc: "libssh2_init".}

proc libssh2_exit*(): void {.importc: "libssh2_exit".}

proc libssh2_free*(session: ptr LIBSSH2_SESSION, `ptr`: pointer): void {.importc: "libssh2_free".}

proc libssh2_session_supported_algs*(
    session: ptr LIBSSH2_SESSION,
    method_type: cint,
    algs: ptr ptr ptr char,
): cint {.importc: "libssh2_session_supported_algs".}

proc libssh2_session_init_ex*(
    my_alloc: proc (a0: csize_t, a1: ptr pointer): pointer,
    my_free: proc (a0: pointer, a1: ptr pointer): void,
    my_realloc: proc (a0: pointer, a1: csize_t, a2: ptr pointer): pointer,
    abstract: pointer,
): ptr LIBSSH2_SESSION {.importc: "libssh2_session_init_ex".}

proc libssh2_session_abstract*(session: ptr LIBSSH2_SESSION): ptr pointer {.importc: "libssh2_session_abstract".}

proc libssh2_session_callback_set2*(
    session: ptr LIBSSH2_SESSION,
    cbtype: cint,
    callback: ptr libssh2_cb_generic,
): ptr libssh2_cb_generic {.importc: "libssh2_session_callback_set2".}

proc libssh2_session_callback_set*(
    session: ptr LIBSSH2_SESSION,
    cbtype: cint,
    callback: pointer,
): pointer {.importc: "libssh2_session_callback_set".}

proc libssh2_session_banner_set*(session: ptr LIBSSH2_SESSION, banner: cstring): cint {.importc: "libssh2_session_banner_set".}

proc libssh2_banner_set*(session: ptr LIBSSH2_SESSION, banner: cstring): cint {.importc: "libssh2_banner_set".}

proc libssh2_session_startup*(session: ptr LIBSSH2_SESSION, sock: cint): cint {.importc: "libssh2_session_startup".}

proc libssh2_session_handshake*(session: ptr LIBSSH2_SESSION, sock: libssh2_socket_t): cint {.importc: "libssh2_session_handshake".}

proc libssh2_session_disconnect_ex*(
    session: ptr LIBSSH2_SESSION,
    reason: cint,
    description: cstring,
    lang: cstring,
): cint {.importc: "libssh2_session_disconnect_ex".}

proc libssh2_session_free*(session: ptr LIBSSH2_SESSION): cint {.importc: "libssh2_session_free".}

proc libssh2_hostkey_hash*(session: ptr LIBSSH2_SESSION, hash_type: cint): cstring {.importc: "libssh2_hostkey_hash".}

proc libssh2_session_hostkey*(
    session: ptr LIBSSH2_SESSION,
    len: ptr csize_t,
    `type`: ptr cint,
): cstring {.importc: "libssh2_session_hostkey".}

proc libssh2_session_method_pref*(
    session: ptr LIBSSH2_SESSION,
    method_type: cint,
    prefs: cstring,
): cint {.importc: "libssh2_session_method_pref".}

proc libssh2_session_methods*(session: ptr LIBSSH2_SESSION, method_type: cint): cstring {.importc: "libssh2_session_methods".}

proc libssh2_session_last_error*(
    session: ptr LIBSSH2_SESSION,
    errmsg: cstringArray,
    errmsg_len: ptr cint,
    want_buf: cint,
): cint {.importc: "libssh2_session_last_error".}

proc libssh2_session_last_errno*(session: ptr LIBSSH2_SESSION): cint {.importc: "libssh2_session_last_errno".}

proc libssh2_session_set_last_error*(
    session: ptr LIBSSH2_SESSION,
    errcode: cint,
    errmsg: cstring,
): cint {.importc: "libssh2_session_set_last_error".}

proc libssh2_session_block_directions*(session: ptr LIBSSH2_SESSION): cint {.importc: "libssh2_session_block_directions".}

proc libssh2_session_flag*(
    session: ptr LIBSSH2_SESSION,
    flag: cint,
    value: cint,
): cint {.importc: "libssh2_session_flag".}

proc libssh2_session_banner_get*(session: ptr LIBSSH2_SESSION): cstring {.importc: "libssh2_session_banner_get".}

proc libssh2_userauth_list*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: cuint,
): ptr char {.importc: "libssh2_userauth_list".}

proc libssh2_userauth_banner*(session: ptr LIBSSH2_SESSION, banner: cstringArray): cint {.importc: "libssh2_userauth_banner".}

proc libssh2_userauth_authenticated*(session: ptr LIBSSH2_SESSION): cint {.importc: "libssh2_userauth_authenticated".}

proc libssh2_userauth_password_ex*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: cuint,
    password: cstring,
    password_len: cuint,
    passwd_change_cb: proc (a0: ptr LIBSSH2_SESSION, a1: cstringArray, a2: ptr cint, a3: ptr pointer): void,
): cint {.importc: "libssh2_userauth_password_ex".}

proc libssh2_userauth_publickey_fromfile_ex*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: cuint,
    publickey: cstring,
    privatekey: cstring,
    passphrase: cstring,
): cint {.importc: "libssh2_userauth_publickey_fromfile_ex".}

proc libssh2_userauth_publickey*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    pubkeydata: cstring,
    pubkeydata_len: csize_t,
    sign_callback: proc (a0: ptr LIBSSH2_SESSION, a1: cstringArray, a2: ptr csize_t, a3: cstring, a4: csize_t, a5: ptr pointer): cint,
    abstract: ptr pointer,
): cint {.importc: "libssh2_userauth_publickey".}

proc libssh2_userauth_hostbased_fromfile_ex*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: cuint,
    publickey: cstring,
    privatekey: cstring,
    passphrase: cstring,
    hostname: cstring,
    hostname_len: cuint,
    local_username: cstring,
    local_username_len: cuint,
): cint {.importc: "libssh2_userauth_hostbased_fromfile_ex".}

proc libssh2_userauth_publickey_frommemory*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: csize_t,
    publickeyfiledata: cstring,
    publickeyfiledata_len: csize_t,
    privatekeyfiledata: cstring,
    privatekeyfiledata_len: csize_t,
    passphrase: cstring,
): cint {.importc: "libssh2_userauth_publickey_frommemory".}

proc libssh2_userauth_keyboard_interactive_ex*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: cuint,
    response_callback: proc (a0: cstring, a1: cint, a2: cstring, a3: cint, a4: cint, a5: ptr LIBSSH2_USERAUTH_KBDINT_PROMPT, a6: ptr LIBSSH2_USERAUTH_KBDINT_RESPONSE, a7: ptr pointer): void,
): cint {.importc: "libssh2_userauth_keyboard_interactive_ex".}

proc libssh2_userauth_publickey_sk*(
    session: ptr LIBSSH2_SESSION,
    username: cstring,
    username_len: csize_t,
    pubkeydata: cstring,
    pubkeydata_len: csize_t,
    privatekeydata: cstring,
    privatekeydata_len: csize_t,
    passphrase: cstring,
    sign_callback: proc (a0: ptr LIBSSH2_SESSION, a1: ptr LIBSSH2_SK_SIG_INFO, a2: cstring, a3: csize_t, a4: cint, a5: uint8, a6: cstring, a7: cstring, a8: csize_t, a9: ptr pointer): cint,
    abstract: ptr pointer,
): cint {.importc: "libssh2_userauth_publickey_sk".}

proc libssh2_poll*(
    fds: ptr LIBSSH2_POLLFD,
    nfds: cuint,
    timeout: clong,
): cint {.importc: "libssh2_poll".}

proc libssh2_channel_open_ex*(
    session: ptr LIBSSH2_SESSION,
    channel_type: cstring,
    channel_type_len: cuint,
    window_size: cuint,
    packet_size: cuint,
    message: cstring,
    message_len: cuint,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_channel_open_ex".}

proc libssh2_channel_direct_tcpip_ex*(
    session: ptr LIBSSH2_SESSION,
    host: cstring,
    port: cint,
    shost: cstring,
    sport: cint,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_channel_direct_tcpip_ex".}

proc libssh2_channel_direct_streamlocal_ex*(
    session: ptr LIBSSH2_SESSION,
    socket_path: cstring,
    shost: cstring,
    sport: cint,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_channel_direct_streamlocal_ex".}

proc libssh2_channel_forward_listen_ex*(
    session: ptr LIBSSH2_SESSION,
    host: cstring,
    port: cint,
    bound_port: ptr cint,
    queue_maxsize: cint,
): ptr LIBSSH2_LISTENER {.importc: "libssh2_channel_forward_listen_ex".}

proc libssh2_channel_forward_cancel*(listener: ptr LIBSSH2_LISTENER): cint {.importc: "libssh2_channel_forward_cancel".}

proc libssh2_channel_forward_accept*(listener: ptr LIBSSH2_LISTENER): ptr LIBSSH2_CHANNEL {.importc: "libssh2_channel_forward_accept".}

proc libssh2_channel_setenv_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    varname: cstring,
    varname_len: cuint,
    value: cstring,
    value_len: cuint,
): cint {.importc: "libssh2_channel_setenv_ex".}

proc libssh2_channel_request_auth_agent*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_request_auth_agent".}

proc libssh2_channel_request_pty_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    term: cstring,
    term_len: cuint,
    modes: cstring,
    modes_len: cuint,
    width: cint,
    height: cint,
    width_px: cint,
    height_px: cint,
): cint {.importc: "libssh2_channel_request_pty_ex".}

proc libssh2_channel_request_pty_size_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    width: cint,
    height: cint,
    width_px: cint,
    height_px: cint,
): cint {.importc: "libssh2_channel_request_pty_size_ex".}

proc libssh2_channel_x11_req_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    single_connection: cint,
    auth_proto: cstring,
    auth_cookie: cstring,
    screen_number: cint,
): cint {.importc: "libssh2_channel_x11_req_ex".}

proc libssh2_channel_signal_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    signame: cstring,
    signame_len: csize_t,
): cint {.importc: "libssh2_channel_signal_ex".}

proc libssh2_channel_process_startup*(
    channel: ptr LIBSSH2_CHANNEL,
    request: cstring,
    request_len: cuint,
    message: cstring,
    message_len: cuint,
): cint {.importc: "libssh2_channel_process_startup".}

proc libssh2_channel_read_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    stream_id: cint,
    buf: ptr char,
    buflen: csize_t,
): csize_t {.importc: "libssh2_channel_read_ex".}

proc libssh2_poll_channel_read*(channel: ptr LIBSSH2_CHANNEL, extended: cint): cint {.importc: "libssh2_poll_channel_read".}

proc libssh2_channel_window_read_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    read_avail: ptr culong,
    window_size_initial: ptr culong,
): culong {.importc: "libssh2_channel_window_read_ex".}

proc libssh2_channel_receive_window_adjust*(
    channel: ptr LIBSSH2_CHANNEL,
    adjustment: culong,
    force: char,
): culong {.importc: "libssh2_channel_receive_window_adjust".}

proc libssh2_channel_receive_window_adjust2*(
    channel: ptr LIBSSH2_CHANNEL,
    adjustment: culong,
    force: char,
    storewindow: ptr cuint,
): cint {.importc: "libssh2_channel_receive_window_adjust2".}

proc libssh2_channel_write_ex*(
    channel: ptr LIBSSH2_CHANNEL,
    stream_id: cint,
    buf: cstring,
    buflen: csize_t,
): csize_t {.importc: "libssh2_channel_write_ex".}

proc libssh2_channel_window_write_ex*(channel: ptr LIBSSH2_CHANNEL, window_size_initial: ptr culong): culong {.importc: "libssh2_channel_window_write_ex".}

proc libssh2_session_set_blocking*(session: ptr LIBSSH2_SESSION, blocking: cint): void {.importc: "libssh2_session_set_blocking".}

proc libssh2_session_get_blocking*(session: ptr LIBSSH2_SESSION): cint {.importc: "libssh2_session_get_blocking".}

proc libssh2_channel_set_blocking*(channel: ptr LIBSSH2_CHANNEL, blocking: cint): void {.importc: "libssh2_channel_set_blocking".}

proc libssh2_session_set_timeout*(session: ptr LIBSSH2_SESSION, timeout: clong): void {.importc: "libssh2_session_set_timeout".}

proc libssh2_session_get_timeout*(session: ptr LIBSSH2_SESSION): clong {.importc: "libssh2_session_get_timeout".}

proc libssh2_session_set_read_timeout*(session: ptr LIBSSH2_SESSION, timeout: clong): void {.importc: "libssh2_session_set_read_timeout".}

proc libssh2_session_get_read_timeout*(session: ptr LIBSSH2_SESSION): clong {.importc: "libssh2_session_get_read_timeout".}

proc libssh2_channel_handle_extended_data*(channel: ptr LIBSSH2_CHANNEL, ignore_mode: cint): void {.importc: "libssh2_channel_handle_extended_data".}

proc libssh2_channel_handle_extended_data2*(channel: ptr LIBSSH2_CHANNEL, ignore_mode: cint): cint {.importc: "libssh2_channel_handle_extended_data2".}

proc libssh2_channel_flush_ex*(channel: ptr LIBSSH2_CHANNEL, streamid: cint): cint {.importc: "libssh2_channel_flush_ex".}

proc libssh2_channel_get_exit_status*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_get_exit_status".}

proc libssh2_channel_get_exit_signal*(
    channel: ptr LIBSSH2_CHANNEL,
    exitsignal: cstringArray,
    exitsignal_len: ptr csize_t,
    errmsg: cstringArray,
    errmsg_len: ptr csize_t,
    langtag: cstringArray,
    langtag_len: ptr csize_t,
): cint {.importc: "libssh2_channel_get_exit_signal".}

proc libssh2_channel_send_eof*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_send_eof".}

proc libssh2_channel_eof*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_eof".}

proc libssh2_channel_wait_eof*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_wait_eof".}

proc libssh2_channel_close*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_close".}

proc libssh2_channel_wait_closed*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_wait_closed".}

proc libssh2_channel_free*(channel: ptr LIBSSH2_CHANNEL): cint {.importc: "libssh2_channel_free".}

proc libssh2_scp_recv*(
    session: ptr LIBSSH2_SESSION,
    path: cstring,
    sb: ptr stat,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_scp_recv".}

proc libssh2_scp_recv2*(
    session: ptr LIBSSH2_SESSION,
    path: cstring,
    sb: ptr libssh2_struct_stat,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_scp_recv2".}

proc libssh2_scp_send_ex*(
    session: ptr LIBSSH2_SESSION,
    path: cstring,
    mode: cint,
    size: csize_t,
    mtime: clong,
    atime: clong,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_scp_send_ex".}

proc libssh2_scp_send64*(
    session: ptr LIBSSH2_SESSION,
    path: cstring,
    mode: cint,
    size: libssh2_int64_t,
    mtime: time_t,
    atime: time_t,
): ptr LIBSSH2_CHANNEL {.importc: "libssh2_scp_send64".}

proc libssh2_base64_decode*(
    session: ptr LIBSSH2_SESSION,
    dest: cstringArray,
    dest_len: ptr cuint,
    src: cstring,
    src_len: cuint,
): cint {.importc: "libssh2_base64_decode".}

proc libssh2_version*(req_version_num: cint): cstring {.importc: "libssh2_version".}

proc libssh2_crypto_engine*(): libssh2_crypto_engine_t {.importc: "libssh2_crypto_engine".}

proc libssh2_knownhost_init*(session: ptr LIBSSH2_SESSION): ptr LIBSSH2_KNOWNHOSTS {.importc: "libssh2_knownhost_init".}

proc libssh2_knownhost_add*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    host: cstring,
    salt: cstring,
    key: cstring,
    keylen: csize_t,
    typemask: cint,
    store: ptr ptr libssh2_knownhost,
): cint {.importc: "libssh2_knownhost_add".}

proc libssh2_knownhost_addc*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    host: cstring,
    salt: cstring,
    key: cstring,
    keylen: csize_t,
    comment: cstring,
    commentlen: csize_t,
    typemask: cint,
    store: ptr ptr libssh2_knownhost,
): cint {.importc: "libssh2_knownhost_addc".}

proc libssh2_knownhost_check*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    host: cstring,
    key: cstring,
    keylen: csize_t,
    typemask: cint,
    knownhost: ptr ptr libssh2_knownhost,
): cint {.importc: "libssh2_knownhost_check".}

proc libssh2_knownhost_checkp*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    host: cstring,
    port: cint,
    key: cstring,
    keylen: csize_t,
    typemask: cint,
    knownhost: ptr ptr libssh2_knownhost,
): cint {.importc: "libssh2_knownhost_checkp".}

proc libssh2_knownhost_del*(hosts: ptr LIBSSH2_KNOWNHOSTS, entry: ptr libssh2_knownhost): cint {.importc: "libssh2_knownhost_del".}

proc libssh2_knownhost_free*(hosts: ptr LIBSSH2_KNOWNHOSTS): void {.importc: "libssh2_knownhost_free".}

proc libssh2_knownhost_readline*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    line: cstring,
    len: csize_t,
    `type`: cint,
): cint {.importc: "libssh2_knownhost_readline".}

proc libssh2_knownhost_readfile*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    filename: cstring,
    `type`: cint,
): cint {.importc: "libssh2_knownhost_readfile".}

proc libssh2_knownhost_writeline*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    known: ptr libssh2_knownhost,
    buffer: ptr char,
    buflen: csize_t,
    outlen: ptr csize_t,
    `type`: cint,
): cint {.importc: "libssh2_knownhost_writeline".}

proc libssh2_knownhost_writefile*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    filename: cstring,
    `type`: cint,
): cint {.importc: "libssh2_knownhost_writefile".}

proc libssh2_knownhost_get*(
    hosts: ptr LIBSSH2_KNOWNHOSTS,
    store: ptr ptr libssh2_knownhost,
    prev: ptr libssh2_knownhost,
): cint {.importc: "libssh2_knownhost_get".}

proc libssh2_agent_init*(session: ptr LIBSSH2_SESSION): ptr LIBSSH2_AGENT {.importc: "libssh2_agent_init".}

proc libssh2_agent_connect*(agent: ptr LIBSSH2_AGENT): cint {.importc: "libssh2_agent_connect".}

proc libssh2_agent_list_identities*(agent: ptr LIBSSH2_AGENT): cint {.importc: "libssh2_agent_list_identities".}

proc libssh2_agent_get_identity*(
    agent: ptr LIBSSH2_AGENT,
    store: ptr ptr libssh2_agent_publickey,
    prev: ptr libssh2_agent_publickey,
): cint {.importc: "libssh2_agent_get_identity".}

proc libssh2_agent_userauth*(
    agent: ptr LIBSSH2_AGENT,
    username: cstring,
    identity: ptr libssh2_agent_publickey,
): cint {.importc: "libssh2_agent_userauth".}

proc libssh2_agent_sign*(
    agent: ptr LIBSSH2_AGENT,
    identity: ptr libssh2_agent_publickey,
    sig: cstringArray,
    s_len: ptr csize_t,
    data: cstring,
    d_len: csize_t,
    `method`: cstring,
    method_len: cuint,
): cint {.importc: "libssh2_agent_sign".}

proc libssh2_agent_disconnect*(agent: ptr LIBSSH2_AGENT): cint {.importc: "libssh2_agent_disconnect".}

proc libssh2_agent_free*(agent: ptr LIBSSH2_AGENT): void {.importc: "libssh2_agent_free".}

proc libssh2_agent_set_identity_path*(agent: ptr LIBSSH2_AGENT, path: cstring): void {.importc: "libssh2_agent_set_identity_path".}

proc libssh2_agent_get_identity_path*(agent: ptr LIBSSH2_AGENT): cstring {.importc: "libssh2_agent_get_identity_path".}

proc libssh2_keepalive_config*(
    session: ptr LIBSSH2_SESSION,
    want_reply: cint,
    interval: cuint,
): void {.importc: "libssh2_keepalive_config".}

proc libssh2_keepalive_send*(session: ptr LIBSSH2_SESSION, seconds_to_next: ptr cint): cint {.importc: "libssh2_keepalive_send".}

proc libssh2_trace*(session: ptr LIBSSH2_SESSION, bitmask: cint): cint {.importc: "libssh2_trace".}

proc libssh2_trace_sethandler*(
    session: ptr LIBSSH2_SESSION,
    context: pointer,
    callback: libssh2_trace_handler_func,
): cint {.importc: "libssh2_trace_sethandler".}