use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: omitted key uses the default client identity
--- http_config
    error_abuse_zone zone=test:1m
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

=== TEST 6: persist_secret rejects 1-byte key
--- http_config
    error_abuse_zone zone=test6:1m key=$binary_remote_addr
                     persist=/tmp/test6.bin persist_secret=00;
--- config
    location = /ok {
        error_abuse zone=test6;
        empty_gif;
    }
--- must_die
--- error_log: persist_secret: min 16 bytes (32 hex chars); got 1 bytes

=== TEST 7: persist_secret rejects 15-byte key
--- http_config
    error_abuse_zone zone=test7:1m key=$binary_remote_addr
                     persist=/tmp/test7.bin persist_secret=000102030405060708090a0b0c0d0e;
--- config
    location = /ok {
        error_abuse zone=test7;
        empty_gif;
    }
--- must_die
--- error_log: persist_secret: min 16 bytes (32 hex chars); got 15 bytes

=== TEST 8: persist_secret accepts 16-byte key
--- http_config
    error_abuse_zone zone=test8:1m key=$binary_remote_addr
                     persist=/tmp/test8.bin persist_secret=000102030405060708090a0b0c0d0e0f;
--- config
    location = /ok {
        error_abuse zone=test8;
        empty_gif;
    }
--- pipelined_requests eval
["GET /ok"]
--- error_code eval
[200]

=== TEST 9: persist_secret accepts 32-byte key (recommended)
--- http_config
    error_abuse_zone zone=test9:1m key=$binary_remote_addr
                     persist=/tmp/test9.bin persist_secret=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
--- config
    location = /ok {
        error_abuse zone=test9;
        empty_gif;
    }
--- pipelined_requests eval
["GET /ok"]
--- error_code eval
[200]

=== TEST 10: mixed-case persist_secret name does not leak the value
--- http_config
    error_abuse_zone zone=test10:1m key=$binary_remote_addr
                     persist=/tmp/test10.bin
                     Persist_Secret=a1b2c3d4e5f60718293a4b5c6d7e8f90;  # gitleaks:allow (test canary)
--- config
    location = /ok {
        error_abuse zone=test10;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "<redacted>"
--- no_error_log
a1b2c3d4e5f60718293a4b5c6d7e8f90

=== TEST 11: upper-case redis password name does not leak the value
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390 PASSWORD=canary11upperpass;  # gitleaks:allow (test canary)
    error_abuse_zone zone=test11:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test11;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_redis parameter "<redacted>"
--- no_error_log
canary11upperpass

=== TEST 12: misspelled persist_secret keeps the name but redacts the value
--- http_config
    error_abuse_zone zone=test12:1m key=$binary_remote_addr
                     persist=/tmp/test12.bin
                     persist_secrt=0f1e2d3c4b5a69788796a5b4c3d2e1f0;
--- config
    location = /ok {
        error_abuse zone=test12;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "persist_secrt=<redacted>"
--- no_error_log
0f1e2d3c4b5a69788796a5b4c3d2e1f0

=== TEST 13: misspelled redis password keeps the name but redacts the value
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390 passwd=canary13typopass;  # gitleaks:allow (test canary)
    error_abuse_zone zone=test13:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test13;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_redis parameter "passwd=<redacted>"
--- no_error_log
canary13typopass

=== TEST 14: password on error_abuse_zone does not leak the value
--- http_config
    error_abuse_zone zone=test14:1m key=$binary_remote_addr
                     password=canary14zonepass;  # gitleaks:allow (test canary)
--- config
    location = /ok {
        error_abuse zone=test14;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "password=<redacted>"
--- no_error_log
canary14zonepass

=== TEST 15: persist_secret on error_abuse_redis does not leak the value
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390
                      persist_secret=1234abcd5678ef901234abcd5678ef90;  # gitleaks:allow (test canary)
    error_abuse_zone zone=test15:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test15;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_redis parameter "persist_secret=<redacted>"
--- no_error_log
1234abcd5678ef901234abcd5678ef90

=== TEST 16: password on error_abuse does not leak the value
--- http_config
    error_abuse_zone zone=test16:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test16 password=canary16enablepass;  # gitleaks:allow (test canary)
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse parameter "password=<redacted>"
--- no_error_log
canary16enablepass

=== TEST 17: duplicate persist_secret does not leak the value
--- http_config
    error_abuse_zone zone=test17:1m key=$binary_remote_addr
                     persist=/tmp/test17.bin
                     persist_secret=00112233445566778899aabbccddeeff  # gitleaks:allow (test canary)
                     persist_secret=ffeeddccbbaa99887766554433221100;  # gitleaks:allow (test canary)
--- config
    location = /ok {
        error_abuse zone=test17;
        empty_gif;
    }
--- must_die
--- error_log: duplicate error_abuse_zone parameter "persist_secret=<redacted>"
--- no_error_log
00112233445566778899aabbccddeeff
ffeeddccbbaa99887766554433221100

=== TEST 18: base64-padded value is redacted whole
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390 Y2FuYXJ5MThCYXNlNjQ=;
    error_abuse_zone zone=test18:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test18;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_redis parameter "<redacted>"
--- no_error_log
Y2FuYXJ5MThCYXNlNjQ

=== TEST 19: bare token without "=" is redacted whole
--- http_config
    error_abuse_zone zone=test19:1m key=$binary_remote_addr
                     canary19baretoken;
--- config
    location = /ok {
        error_abuse zone=test19;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "<redacted>"
--- no_error_log
canary19baretoken

=== TEST 20: a 32-byte unknown name is kept, its value redacted
--- http_config
    error_abuse_zone zone=test20:1m key=$binary_remote_addr
                     abcdefghijklmnopqrstuvwxyz_01234=canary20value;
--- config
    location = /ok {
        error_abuse zone=test20;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "abcdefghijklmnopqrstuvwxyz_01234=<redacted>"
--- no_error_log
canary20value

=== TEST 21: a 33-byte unknown name is redacted whole
--- http_config
    error_abuse_zone zone=test21:1m key=$binary_remote_addr
                     abcdefghijklmnopqrstuvwxyz_012345=canary21value;
--- config
    location = /ok {
        error_abuse zone=test21;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "<redacted>"
--- no_error_log
canary21value
abcdefghijklmnopqrstuvwxyz_012345

=== TEST 22: known non-secret error_abuse_zone value still prints
--- http_config
    error_abuse_zone zone=test22:1m key=$binary_remote_addr threshold=0;
--- config
    location = /ok {
        error_abuse zone=test22;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "threshold=0"

=== TEST 23: known non-secret error_abuse_redis value still prints
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390 timeout=0;
    error_abuse_zone zone=test23:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test23;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_redis parameter "timeout=0"

=== TEST 24: known non-secret error_abuse duplicate still prints
--- http_config
    error_abuse_zone zone=test24:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test24 status=429 status=403;
        empty_gif;
    }
--- must_die
--- error_log: duplicate error_abuse parameter "status=403"

=== TEST 25: rejected zone redis= value is redacted
--- http_config
    error_abuse_zone zone=test25:1m key=$binary_remote_addr
                     redis=redis://:canary25urlpass@127.0.0.1;  # gitleaks:allow (test canary)
--- config
    location = /ok {
        error_abuse zone=test25;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_zone parameter "redis=<redacted>"
--- no_error_log
canary25urlpass

=== TEST 26: known name joined to a second option is redacted
--- http_config
    error_abuse_redis host=127.0.0.1 port=6390password=canary26joined;  # gitleaks:allow (test canary)
    error_abuse_zone zone=test26:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test26;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse_redis parameter "port=<redacted>"
--- no_error_log
canary26joined

=== TEST 27: status list joined to a secret option is redacted
--- http_config
    error_abuse_zone zone=test27:1m key=$binary_remote_addr
                     statuses=404,password=canary27statuses;  # gitleaks:allow (test canary)
--- config
    location = /ok {
        error_abuse zone=test27;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse status list "<redacted>"
--- no_error_log
canary27statuses

=== TEST 28: status list with an empty element and a joined secret is redacted
--- http_config
    error_abuse_zone zone=test28:1m key=$binary_remote_addr
                     statuses=404,,password=canary28statuses;  # gitleaks:allow (test canary)
--- config
    location = /ok {
        error_abuse zone=test28;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse status list "<redacted>" (empty element)
--- no_error_log
canary28statuses

=== TEST 29: status list with an empty element still prints
--- http_config
    error_abuse_zone zone=test29:1m key=$binary_remote_addr statuses=404,,500;
--- config
    location = /ok {
        error_abuse zone=test29;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse status list "404,,500" (empty element)

=== TEST 30: status list with a trailing comma still prints
--- http_config
    error_abuse_zone zone=test30:1m key=$binary_remote_addr statuses=404,;
--- config
    location = /ok {
        error_abuse zone=test30;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse status list "404," (trailing comma)

=== TEST 31: non-numeric status list still prints
--- http_config
    error_abuse_zone zone=test31:1m key=$binary_remote_addr statuses=abc;
--- config
    location = /ok {
        error_abuse zone=test31;
        empty_gif;
    }
--- must_die
--- error_log: invalid error_abuse status list "abc"

=== TEST 32: unknown zone name joined to a secret option is redacted
--- http_config
    error_abuse_zone zone=test32:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=test32password=canary32zonepass;  # gitleaks:allow (test canary)
        empty_gif;
    }
--- must_die
--- error_log: unknown error_abuse zone "<redacted>"
--- no_error_log
canary32zonepass

=== TEST 33: ordinary unknown zone name still prints
--- http_config
    error_abuse_zone zone=test33:1m key=$binary_remote_addr;
--- config
    location = /ok {
        error_abuse zone=nosuch;
        empty_gif;
    }
--- must_die
--- error_log: unknown error_abuse zone "nosuch"

=== TEST 34: empty key is rejected
--- http_config
    error_abuse_zone zone=test34:1m key=;
--- config
    location = /ok { empty_gif; }
--- must_die
--- error_log: invalid error_abuse_zone parameter "key="

=== TEST 35: quoted empty key is rejected
--- http_config
    error_abuse_zone zone=test35:1m "key=";
--- config
    location = /ok { empty_gif; }
--- must_die
--- error_log: invalid error_abuse_zone parameter "key="

=== TEST 36: one-byte literal key remains valid
--- http_config
    error_abuse_zone zone=test36:1m key=x statuses=404 threshold=1;
--- config
    location = /missing { error_abuse zone=test36; return 404; }
    location = /ok { error_abuse zone=test36; empty_gif; }
--- pipelined_requests eval
["GET /missing", "GET /ok"]
--- error_code eval
[404, 429]

=== TEST 37: malformed key expression remains invalid
--- http_config
    error_abuse_zone zone=test37:1m key=${};
--- config
    location = /ok { empty_gif; }
--- must_die
--- error_log: invalid variable name

=== TEST 38: valid key expression preserves empty request values
--- http_config
    error_abuse_zone zone=test38:1m key=$arg_id statuses=404 threshold=1;
--- config
    location = /missing { error_abuse zone=test38; return 404; }
    location = /ok { error_abuse zone=test38; empty_gif; }
--- pipelined_requests eval
["GET /missing", "GET /ok", "GET /missing?id=a", "GET /ok?id=a", "GET /ok?id=b"]
--- error_code eval
[404, 200, 404, 429, 200]
