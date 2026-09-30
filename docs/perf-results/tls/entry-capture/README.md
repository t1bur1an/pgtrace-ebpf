Results of the first TLS capture build, which captured `SSL_write` at entry.
The 30-minute TLS soak (`soak-failed-20260930-0316/`) failed: with a slow
reader, pgbouncer calls `SSL_write` again with the same bytes after a full
socket, and entry capture duplicated them (44,457 orphans). `SSL_write` is
now captured at return; current results are in the parent directory.
