#!/usr/bin/env python3

import os
import math
import hashlib
import datetime
import subprocess

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends.openssl import backend

def timestamp():
  return int(datetime.datetime.now().astimezone(datetime.timezone.utc).timestamp())


def gen_priv_key():
  key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=backend)
  return key


def serialize_sec_key_to_pem(key):
  assert isinstance(key, rsa.RSAPrivateKey)
  pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())
  return pem.decode('utf-8')


def gen_fingerprint_material(key, ts=None):
  assert isinstance(key, rsa.RSAPublicKey)

  pkt_contents = serialize_pub_key_packet_contents(key, ts)

  material = b''
  material += b'\x99'
  material += len(pkt_contents).to_bytes(2, 'big')
  material += pkt_contents

  return material


def fingerprint_pub_key(key, ts=None):
  assert isinstance(key, rsa.RSAPublicKey)

  material = gen_fingerprint_material(key, ts)

  m = hashlib.sha1()
  m.update(material)
  digest = m.digest()
  return digest.hex().encode('utf-8')


def fingerprint_sec_key(key, ts=None):
  assert isinstance(key, rsa.RSAPrivateKey)

  return fingerprint_pub_key(key.public_key(), ts)


def mpi(i):
  bit_width = math.ceil(math.log(i, 2))
  ser_w = bit_width.to_bytes(2, 'big')
  byte_width = (bit_width + 7) // 8
  # ser_w = byte_width.to_bytes(2, 'big')
  ser_i = i.to_bytes(byte_width, 'big')
  ser = ser_w + ser_i
  return ser


def serialize_packet_len(val):
  # short encodings:
  # if val <= 192:
  #   return bytes((val,))
  # if val <= 8383:
  #   rem = val - 192
  #   return bytes((rem >> 8) + 192, rem & 0xFF))

  # just always use the simple one
  return b'\xFF' + val.to_bytes(4, 'big')


def serialize_packet(tag, contents):
  pkt_tag = (0b1100_0000 | tag) # set top two bits
  pkt = bytes((pkt_tag,))
  pkt += serialize_packet_len(len(contents))
  pkt += contents
  return pkt


def serialize_pub_key_packet_contents(key, ts=None):
  assert isinstance(key, rsa.RSAPublicKey)

  # format described in https://tools.ietf.org/html/rfc4880#section-5.5.2

  v = 4
  if ts is None:
    ts = timestamp()
  algo = 3 # RSA Sign-Only: https://tools.ietf.org/html/rfc4880#section-9.1

  key_nums = key.public_numbers()
  key_n = key_nums.n
  key_e = key_nums.e

  key_n_mpi = mpi(key_n)
  key_e_mpi = mpi(key_e)

  contents = b''
  contents += bytes((v,))
  contents += ts.to_bytes(4, 'big')
  contents += bytes((algo,))
  contents += key_n_mpi
  contents += key_e_mpi

  return contents


def serialize_sec_key_packet_contents(key, ts=None):
  assert isinstance(key, rsa.RSAPrivateKey)

  # format described in https://tools.ietf.org/html/rfc4880#section-5.5.3

  pub_contents = serialize_pub_key_packet_contents(key.public_key(), ts)

  encryption = b'\x00' #

  key_nums = key.private_numbers()
  key_d = key_nums.d
  key_p = key_nums.q # note the swap
  key_q = key_nums.p # note the swap

  assert key_p < key_q

  key_u = key_nums.iqmp

  key_num_bytes = b''
  key_num_bytes += mpi(key_d)
  key_num_bytes += mpi(key_p)
  key_num_bytes += mpi(key_q)
  key_num_bytes += mpi(key_u)

  checksum = 0
  for b in key_num_bytes:
    checksum += b
  checksum = checksum & 0xFFFF

  contents = b''
  contents += pub_contents
  contents += encryption
  contents += key_num_bytes
  contents += checksum.to_bytes(2, 'big')

  return contents


def serialize_pub_key_packet(key, ts=None):
  tag = 6 # https://tools.ietf.org/html/rfc4880#section-5.5.1.1
  contents = serialize_pub_key_packet_contents(key, ts)
  pkt = serialize_packet(tag, contents)
  return pkt


def serialize_sec_key_packet(key, ts=None):
  tag = 5 # https://tools.ietf.org/html/rfc4880#section-5.5.1.3
  contents = serialize_sec_key_packet_contents(key, ts)
  pkt = serialize_packet(tag, contents)
  return pkt


def serialize_user_packet():
  tag = 13 # https://tools.ietf.org/html/rfc4880#section-5.11
  contents = b"Zstandard Release Signing Key <signing@zstd.net>"
  pkt = serialize_packet(tag, contents)
  return pkt


def serialize_sec_key_to_gpg(key, ts=None):
  assert isinstance(key, rsa.RSAPrivateKey)

  ser = b''
  ser += serialize_sec_key_packet(key, ts)
  ser += serialize_user_packet()

  return ser


def save_key(key, ts):
  assert isinstance(key, rsa.RSAPrivateKey)

  fpr = fingerprint_sec_key(key, ts)
  pem = serialize_sec_key_to_pem(key)
  gpg = serialize_sec_key_to_gpg(key, ts)

  open(fpr + b".pem", "w").write(pem)
  open(fpr + b".gpg", "wb").write(gpg)


# does the hashing in python (slowly).
def search():
  TARGET = b"28b52ffd"
  # TARGET = b"28b5"
  next_len = 1
  tgt_len = len(TARGET)
  while True:
    print("Generating new key...", timestamp())
    key = gen_priv_key()
    now = timestamp()
    # delta_secs = 60 * 60 * 24 * 31
    delta_secs = 60 * 60 * 24 * 7
    earliest = now - delta_secs
    latest = now + delta_secs
    for ts in range(earliest, latest):
      fpr = fingerprint_sec_key(key, ts)
      # print(fpr)
      if (fpr[-next_len:] == TARGET[:next_len]):
        print(fpr)
        save_key(key, ts)
        next_len = min(next_len + 1, tgt_len)


def main():
  target = b"28b52ffd"
  base_ts = timestamp()
  # delta_secs = 60 * 60 * 24 * 7
  delta_secs = 60 * 60 * 24 * 7
  min_ts = base_ts - delta_secs
  max_ts = base_ts + delta_secs
  while True:
    key = gen_priv_key()
    fpr = fingerprint_sec_key(key, 0)
    # print("Generated new key @", timestamp(), "fpr", fpr)
    fpr_material = gen_fingerprint_material(key.public_key(), 0)
    fn = os.path.join(b"tmp", fpr + b".fingerprint-material")
    with open(fn, "wb") as f:
      f.write(fpr_material)

    cmd = [
      "./collider",
      fn,
      target,
      str(min_ts),
      str(max_ts)
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.check_returncode()

    os.unlink(fn)

    if proc.stderr:
      print(prod.stderr)
    if proc.stdout:
      print(proc.stdout)
      timestamps = [int(l) for l in proc.stdout.split(b"\n") if l]
      for ts in timestamps:
        fpr = fingerprint_sec_key(key, ts)
        if fpr.endswith(target):
          print("Found!:", ts, fpr)
          save_key(key, ts)
        else:
          print(ts, fpr, "doesn't work???")




if __name__ == '__main__':
  main()


# key = gen_priv_key()
# pem = serialize_sec_key_to_pem(key)
# # print(pem)
# gpg = serialize_sec_key_to_gpg(key)
# # print(gpg)
# open("tmp.key", "wb").write(gpg)

# print(fingerprint_sec_key(key))
