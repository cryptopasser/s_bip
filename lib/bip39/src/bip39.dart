import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:hex/hex.dart';
import 'package:s_bip/bip39/src/utils/pbkdf2_helper.dart';
import 'package:s_bip/bip39/src/utils/words_util.dart';

/**
 * @author snakeway
 * @description:
 * @date :2021/7/14
 */

const int SIZE_BYTE = 255;
const INVALID_MNEMONIC = "Invalid mnemonic";
const INVALID_ENTROPY = "Invalid entropy";
const INVALID_CHECKSUM = "Invalid mnemonic checksum";

typedef Uint8List RandomBytes(int size);

int _binaryToByte(String binary) {
  return int.parse(binary, radix: 2);
}

String _bytesToBinary(Uint8List bytes) {
  return bytes.map((byte) => byte.toRadixString(2).padLeft(8, '0')).join('');
}

String _deriveCheckSumBits(Uint8List entropy) {
  int ent = entropy.length * 8;
  int cs = ent ~/ 32;
  Digest hash = sha256.convert(entropy);
  return _bytesToBinary(Uint8List.fromList(hash.bytes)).substring(0, cs);
}

Uint8List _randomBytes(int size) {
  Random random = Random.secure();
  Uint8List bytes = Uint8List(size);
  for (var i = 0; i < size; i++) {
    bytes[i] = random.nextInt(SIZE_BYTE);
  }
  return bytes;
}

String generateMnemonic(
    {int strength = 128, RandomBytes randomBytes = _randomBytes}) {
  assert(strength % 32 == 0);
  Uint8List entropy = randomBytes(strength ~/ 8);
  return entropyToMnemonic(HEX.encode(entropy));
}

String entropyToMnemonic(String entropyString) {
  Uint8List entropy = Uint8List.fromList(HEX.decode(entropyString));
  if (entropy.length < 16) {
    throw ArgumentError(INVALID_ENTROPY);
  }
  if (entropy.length > 32) {
    throw ArgumentError(INVALID_ENTROPY);
  }
  if (entropy.length % 4 != 0) {
    throw ArgumentError(INVALID_ENTROPY);
  }
  String entropyBits = _bytesToBinary(entropy);
  String checksumBits = _deriveCheckSumBits(entropy);
  String bits = entropyBits + checksumBits;
  RegExp regExp = RegExp(r".{1,11}", caseSensitive: false, multiLine: false);
  List chunks = regExp
      .allMatches(bits)
      .map((match) => match.group(0))
      .toList(growable: false);
  List<String> wordList = WORD_LIST_ENGLISH;
  String words =
      chunks.map((binary) => wordList[_binaryToByte(binary)]).join(' ');
  return words;
}

Uint8List mnemonicToSeed(String mnemonic, {String password = ""}) {
  Pbkdf2Helper pbkdf2Helper = Pbkdf2Helper();
  return pbkdf2Helper.process(mnemonic, password: password);
}

String mnemonicToSeedHex(String mnemonic, {String password = ""}) {
  return mnemonicToSeed(mnemonic, password: password).map((byte) {
    return byte.toRadixString(16).padLeft(2, '0');
  }).join('');
}

bool validateMnemonic(String mnemonic) {
  try {
    mnemonicToEntropy(mnemonic);
  } catch (e) {
    print(e);
    return false;
  }
  return true;
}

String mnemonicToEntropy(mnemonic) {
  var words = mnemonic.split(' ');
  if (words.length % 3 != 0) {
    throw ArgumentError(INVALID_MNEMONIC);
  }
  List<String> wordList = WORD_LIST_ENGLISH;
  // convert word indices to 11 bit binary strings
  String bits = words.map((word) {
    final index = wordList.indexOf(word);
    if (index == -1) {
      throw ArgumentError(INVALID_MNEMONIC);
    }
    return index.toRadixString(2).padLeft(11, '0');
  }).join('');
  // split the binary string into ENT/CS
  int dividerIndex = (bits.length / 33).floor() * 32;
  String entropyBits = bits.substring(0, dividerIndex);
  String checkSumBits = bits.substring(dividerIndex);

  // calculate the checksum and compare
  RegExp regex = RegExp(r".{1,8}");
  Uint8List entropyBytes = Uint8List.fromList(regex
      .allMatches(entropyBits)
      .map((match) => _binaryToByte(match.group(0)!))
      .toList(growable: false));
  if (entropyBytes.length < 16) {
    throw StateError(INVALID_ENTROPY);
  }
  if (entropyBytes.length > 32) {
    throw StateError(INVALID_ENTROPY);
  }
  if (entropyBytes.length % 4 != 0) {
    throw StateError(INVALID_ENTROPY);
  }
  String newCheckSum = _deriveCheckSumBits(entropyBytes);
  if (newCheckSum != checkSumBits) {
    throw StateError(INVALID_CHECKSUM);
  }
  return entropyBytes.map((byte) {
    return byte.toRadixString(16).padLeft(2, '0');
  }).join('');
}
