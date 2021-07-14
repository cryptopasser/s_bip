import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';

/**
 * @author snakeway
 * @description:
 * @date :2021/7/14
 */

class Pbkdf2Helper {
  final int blockLength;
  final int iterationCount;
  final int desiredKeyLength;
  final String saltPrefix = "mnemonic";

  PBKDF2KeyDerivator pbkdf2KeyDerivator;

  Pbkdf2Helper({
    this.blockLength = 128,
    this.iterationCount = 2048,
    this.desiredKeyLength = 64,
  }) : pbkdf2KeyDerivator =
            PBKDF2KeyDerivator(HMac(SHA512Digest(), blockLength));

  Uint8List process(String mnemonic, {String password = ""}) {
    Uint8List salt = Uint8List.fromList(utf8.encode(saltPrefix + password));
    pbkdf2KeyDerivator.reset();
    pbkdf2KeyDerivator
        .init(Pbkdf2Parameters(salt, iterationCount, desiredKeyLength));
    return pbkdf2KeyDerivator.process(Uint8List.fromList(mnemonic.codeUnits));
  }
}
