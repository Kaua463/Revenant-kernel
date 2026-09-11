import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trust = load('trust', 'check-stock-module-trust.py')
abi = load('abi', 'audit-rom-module-abi.py')


class ModuleTrust(unittest.TestCase):
    def test_pinned_certificate_and_missing_image_key(self):
        der = trust.certificate_der(Path(__file__).resolve().parents[1] / 'configs/rodin-stock-304-modules.pem')
        with self.assertRaises(ValueError):
            trust.require_embedded(b'kernel without stock key', der)
        trust.require_embedded(b'prefix' + der + b'suffix', der)

    def test_unsigned_and_truncated_modules_rejected(self):
        for value in (b'ELF', trust.MARKER, b'\0' * 12 + trust.MARKER):
            with self.assertRaises(ValueError):
                trust.signed_parts(value)

    def test_signature_split(self):
        content, signature = b'ELF content', b'PKCS7 signature'
        meta = bytes([0, 0, 2, 0, 0, 0, 0, 0]) + struct.pack('>I', len(signature))
        self.assertEqual(trust.signed_parts(content + signature + meta + trust.MARKER), (content, signature))

    def test_version_audit_preserves_signed_elf(self):
        # Minimal AArch64 ELF with a __versions section and a signature trailer.
        names = b'\0.shstrtab\0__versions\0'
        record = struct.pack('<Q', 0x12345678) + b'rfkill_alloc\0'.ljust(56, b'\0')
        data = bytearray(64 + len(names) + len(record))
        data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
        shoff = len(data)
        struct.pack_into('<HHIQQQIHHHHHH', data, 16, 1, 183, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 1)
        data[64:64 + len(names)] = names
        data[64 + len(names):] = record
        data += bytes(64)
        data += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, 64, len(names), 0, 0, 1, 0)
        data += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, 64 + len(names), len(record), 0, 0, 8, 0)
        data += b'signature-preservation-fixture' + trust.MARKER
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'module.ko'
            path.write_bytes(data)
            self.assertEqual(abi.read_versions(path, '/opt/homebrew/opt/llvm/bin/llvm-objcopy'), [('rfkill_alloc', 0x12345678)])
            self.assertEqual(path.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
