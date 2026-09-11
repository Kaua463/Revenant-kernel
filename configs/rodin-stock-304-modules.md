# DyperOS 3.0.304 stock module public certificate

Public certificate only; no private key. Restores the original ROM module
signer's trust through CONFIG_SYSTEM_TRUSTED_KEYS, preserving signature,
protected-export, CRC and vermagic enforcement.

- Source full boot SHA256: `3c555f2f5dda7b6085dd38a2869d23ffe680c05d5bcc59625885b726690a00ce`.
- Decompressed stock Image SHA256: `99485b0132e3aa28f4e965119591c8149fe3c20e7e0fd10d753ef014a582472e`.
- DER offset in decompressed Image: 34118400; length: 1357 bytes.
- DER SHA256: `5ebc9677a7726f47d4ec021753617a197d3777eabce29fb338eddd6a1f3f7424`.
- All 78 modules freshly extracted from the backed-up system_dlkm image pass
  detached CMS signature verification with this pinned certificate.
- Failed run 34551018761 embeds a different generated certificate and omits
  this stock certificate. New builds must include both their own signing key
  and this stock trust anchor. No trusted-key check may be bypassed.

Old local ABI extraction copies were modified by objcopy and lost signature
trailers. Use freshly extracted modules, not those copies, for signature checks.
The read-only ELF parser now preserves all input bytes.

Hardware Wi-Fi/Bluetooth confirmation remains pending a newly built candidate.
The slowdown has not been attributed to a proven specific kernel defect;
generic MediaTek warnings alone are not grounds to patch CPU/GPU behavior.
