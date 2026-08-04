use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: block after configured error threshold
--- http_config
    error_abuse_zone zone=test:1m key=$binary_remote_addr
                     statuses=403,404 interval=10s threshold=3 block=30s;
--- config
    location = /missing {
        error_abuse zone=test status=429;
        return 404;
    }
    # NB: the block is enforced in the preaccess phase. `return` is handled in
    # the rewrite phase and finalizes before preaccess runs, so the enforced
    # request must use a normal content handler (here empty_gif) to reach it.
    location = /ok {
        error_abuse zone=test status=429;
        empty_gif;
    }
--- pipelined_requests eval
["GET /missing", "GET /missing", "GET /missing", "GET /ok"]
--- error_code eval
[404, 404, 404, 429]

=== TEST 2: unconfigured errors are ignored
--- http_config
    error_abuse_zone zone=test2:1m key=$binary_remote_addr
                     statuses=404 interval=10s threshold=2 block=30s;
--- config
    location = /denied {
        error_abuse zone=test2;
        return 403;
    }
--- pipelined_requests eval
["GET /denied", "GET /denied", "GET /denied"]
--- error_code eval
[403, 403, 403]

=== TEST 3: dry run does not reject
--- http_config
    error_abuse_zone zone=test3:1m key=$binary_remote_addr
                     statuses=404 interval=10s threshold=1 block=30s;
--- config
    location = /dry {
        error_abuse zone=test3 dry_run=on;
        return 404;
    }
--- pipelined_requests eval
["GET /dry", "GET /dry"]
--- error_code eval
[404, 404]

=== TEST 4: invalid persist_secret does not leak the key into the error log
--- http_config
    error_abuse_zone zone=test4:1m key=$binary_remote_addr
                     persist=/tmp/test4.bin
                     persist_secret=deadfeedcafebeef0badf00dfeed5a5;
--- config
    location = /ok {
        error_abuse zone=test4;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "persist_secret=<redacted>"
--- no_error_log
deadfeedcafebeef0badf00dfeed5a5

=== TEST 5: duplicate redis password does not leak the value into the error log
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390
                      password=f00dcafebabe5a5a
                      password=f00dcafebabe5a5a;
    error_abuse_zone zone=test5:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test5;
        empty_gif;
    }
--- must_die
--- error_log: duplicate error_abuse_redis parameter "password=<redacted>"
--- no_error_log
f00dcafebabe5a5a
