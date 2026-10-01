# Windows package — run steps

1. Keep Exit disabled in the client config (`enable=false` under `[exit]`).
2. Start `session-router.exe`. The tunnel adapter `sr-tun0` appears after a few seconds.
3. Set tunnel DNS to the local resolver (the zip does **not** run this for you):

```
netsh interface ip set dns name="sr-tun0" static 127.0.0.1 primary validate=no
```

Or run the optional pre-flight script from this folder (same steps: wait for `sr-tun0`, set DNS, show DNS):

```
powershell -ExecutionPolicy Bypass -File tunnel-dns-preflight.ps1
```

4. Verify:

```
netsh interface ip show dns name="sr-tun0"
```

Expected: statically configured DNS server `127.0.0.1`.
