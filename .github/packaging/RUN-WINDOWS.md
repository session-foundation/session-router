# Windows package — run steps

Keep Exit disabled in the client config (`enable=false` under `[exit]`). After
starting `session-router.exe`, the tunnel adapter `sr-tun0` appears. Set the
tunnel DNS to the local resolver:

```
netsh interface ip set dns name="sr-tun0" static 127.0.0.1 primary validate=no
```

Run that command once `sr-tun0` exists (typically a few seconds after launch).
Verify with:

```
netsh interface ip show dns name="sr-tun0"
```

Expected: statically configured DNS server `127.0.0.1`.
