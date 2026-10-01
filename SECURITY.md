# Security Notes

1. Never invent or chain arbitrary ciphers for visual effect.
2. Do not put Secret Key in URLs.
3. Treat access codes as bearer credentials.
4. Do not log plaintext, Secret Key, or raw Access Code.
5. AES-GCM requires unique IVs; this project generates a fresh random 96-bit IV per encryption.
6. Server-side data should be considered confidential metadata even though it does not contain plaintext.
7. Production owner authentication and protected handoff should be added before treating this as a high-assurance security system.
