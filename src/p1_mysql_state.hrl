-record(state, {
    mysql_version,
    log_fun,
    socket,
    data = <<>>,
    prepared = #{}
}).
