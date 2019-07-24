#! /usr/bin/env python2

# Tested with lief==0.9.0.

from __future__ import print_function

import os
import sys
import lief
import string
import struct
import tempfile

from collections import Counter


SIZES = Counter()

# Arbitrary upper bound on configuration size.
MAX_CONFIG_SIZE = 0x600

TYPE = {
    lief.PE.HEADER_CHARACTERISTICS.EXECUTABLE_IMAGE: 'exe',
    lief.PE.HEADER_CHARACTERISTICS.DLL: 'dll',
    lief.PE.HEADER_CHARACTERISTICS.SYSTEM: 'sys',
}


def pretty_print(config):
    i = 0
    n = len(config)

    # Print all data and its respective offset while skipping zero bytes.
    while i < n:
        sys.stdout.write('\n\t+0x{:03X}:  '.format(i))

        data = []
        while i < n and config[i]:
            data.append(chr(config[i]))
            i += 1

        if all(x in string.printable for x in data):
            data = '"{}"'.format(''.join(data))
        else:
            data = ''.join('%02X ' % ord(x) for x in data)

        sys.stdout.write(data)
        while i < n and not config[i]:
            i += 1

    print('\n')


def handle_file(exe, path, data, kind):
    global SIZES
    SIZES[len(data)] += 1

    print('-' * 100)
    print('')

    print('{}: Parsed configuration ({}).\n'.format(path, kind))
    print('- Size:    0x{:03X}'.format(len(data)))

    if exe is not None:
        sys.stdout.write('- Type:    ')
        for k, v in TYPE.iteritems():
            if exe.header.has_characteristic(k):
                sys.stdout.write('{} '.format(v))

        if len(exe.exported_functions):
            # Print the first three exported functions for quick clustering.
            print('\n- Exports: #{}'.format(len(exe.exported_functions)))

            for i, exp in enumerate(exe.exported_functions[:3]):
                print('           {}'.format(exp))

            if len(exe.exported_functions) > 3:
                print('           ...')

        if len(exe.signature.certificates):
            print('\n- Certificates:\n')
            for cert in exe.signature.certificates:
                print(cert)

    # print(exe.rich_header)
    print('\n- Configuration:')
    pretty_print(data)


def decrypt_overlay(overlay):
    # Most likely, the first entry is a path somewhere into C:\, so guess 'C'
    # as the first character and try the resulting key first. Only then test
    # all other potential keys.
    k = overlay[0] ^ ord('C')
    keys = [k, 0x99, 0x9d] + list(range(256))

    plain = []
    for k in keys:
        plain = [o ^ ((k + i) & 0xff) for i, o in enumerate(overlay)]
        candidate = Counter(plain).most_common(1)
        if not candidate:
            continue

        # If the zero byte is most common, the decryption most likely
        # succeeded. Configurations are often populated sparsely.
        byte, _count = candidate[0]
        if byte == 0:
            break

    return plain


def fix_header(data, offset):
    # Fix up headers, assuming PE64 for simplicity (we do not want to run this
    # anyway.)
    data[0:2] = '\x4d\x5a'
    data[offset:offset + 4] = '\x50\x45\x00\x00'

    data[offset + 4:offset + 6] = '\x4c\x01'
    data[offset + 0x16:offset + 0x18] = '\x02\x00'
    data[offset + 0x18:offset + 0x1a] = '\x0b\x02'
    data[offset + 0x5c:offset + 0x5e] = '\x02\x00'

    return data


def swap(b):
    return (b >> 4) | ((b & 0xf) << 4)


def decrypt(data, offset):
    data = [swap(d ^ 0x36) for d in data]
    data = bytearray(chr(d) for d in data)

    return data


def check_file(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    magic = struct.unpack('<H', data[:2])[0]
    if magic == 0x5a4d:
        return path

    offset = struct.unpack('<I', data[0x3c:(0x3c + 4)])[0]

    # Assume encryption with key 0x36 (we did not encounter anthing else yet.)
    if magic == 0x3636:
        data = decrypt(data, offset)

        offset = struct.unpack('<I', data[0x3c:(0x3c + 4)])[0]
        data = fix_header(data, offset)

    elif data[offset:offset + 2] == '\x50\x45':
        data[0:2] = '\x4d\x5a'

    elif magic == 0:
        data = fix_header(data, offset)

    else:
        return path

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        new_path = f.name

    return new_path


MAGIC = [
    b'\xff\xd8\xff\xe0\x00\x00\x00\x00\x00\x00',
    b'Cooper',
]


def detect_inline_config(data, magic):
    m = data.find(magic)
    if m == -1:
        return None

    x = m + len(magic)

    # Skip any null bytes following our magic number. This works as the rolling
    # is unlikely to contain repetitive bytes right at the beginning.
    while data[x] == '\x00':
        x += 1

    # Skipping too many bytes indicates a different scenario.
    if (x - m) > 100:
        return None

    # Find the end of the configuration -- ideally, we would get this from the
    # binary itself, but let's not hack some assembly fingerprint together.
    # Same reasoning as above, unlikely to have repetitive bytes in rolling
    # xor.
    y = data.find(b'\x00\x00', x)
    if y == -1:
        return None

    # These configs are rather short so let's try not to guess a key based on
    # the number of zeroes. We did not encounter any other key anyways.
    config = data[x:y]
    config = [ord(x) ^ ((0x99 + i) & 0xff) for i, x in enumerate(config)]
    return ''.join(map(chr, config))


def main():
    if len(sys.argv) < 2:
        print('Usage: parse.py <directory_with_samples>')
        return

    # lief.Logger.enable()

    for root, _dirs, files in os.walk(sys.argv[1]):
        for path in files:
            path = os.path.join(root, path)

            # Fix up the file, if we have to. There are three scenarios:
            # - Its MZ header has been mangled with.
            # - Most of its header has been stripped for manually mapping.
            # - It is "encrypted".
            path = check_file(path)

            exe = lief.parse(path)
            with open(path, 'rb') as f:
                data = f.read()

            # The configuration may be stored inline and hinted at by a marker.
            for magic in MAGIC:
                config = detect_inline_config(data, magic)
                if config is None:
                    continue

                if len(config) > MAX_CONFIG_SIZE:
                    continue

                handle_file(exe, path, bytearray(config), 'inline')

            if not exe:
                continue

            if exe.overlay is None:
                continue

            # Otherwise, look for the configuration in its overlay.
            try:
                n = 0
                overlay = exe.overlay

                # We could simply just parse the last dword to read the
                # configuration size, but some samples are broken in that they
                # append additional zero bytes to the overlay. This code tries
                # to detect and skip these.
                while not n:
                    n = ''.join(chr(o) for o in overlay[-4:])
                    n = struct.unpack('<I', n)[0]
                    if not n:
                        overlay = overlay[:-4]

                if n > MAX_CONFIG_SIZE:
                    continue

                overlay = overlay[-n - 4:]
                overlay = decrypt_overlay(overlay)

                handle_file(exe, path, overlay, 'overlay')
            except Exception as _:
                pass

    print('\n\n\nConfiguration sizes:\n')
    for k, v in SIZES.most_common():
        print('  - 0x{:04X}: #{}'.format(k, v))


if __name__ == '__main__':
    main()
