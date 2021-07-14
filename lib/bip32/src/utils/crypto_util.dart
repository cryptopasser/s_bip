/**
 * @author snakeway
 * @description:
 * @date :2021/7/14
 */
import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/digests/ripemd160.dart";
import "package:pointycastle/digests/sha256.dart";
import "package:pointycastle/digests/sha512.dart";
import "package:pointycastle/macs/hmac.dart";

final Uint8List ZERO1 = Uint8List.fromList([0]);
final Uint8List ONE1 = Uint8List.fromList([1]);

Uint8List hash160(Uint8List buffer) {
  Uint8List bytes = SHA256Digest().process(buffer);
  return RIPEMD160Digest().process(bytes);
}

Uint8List hMacSHA512(Uint8List key, Uint8List data) {
  HMac hMac = HMac(SHA512Digest(), 128);
  hMac.init(KeyParameter(key));
  return hMac.process(data);
}
