import 'package:s_bip/bip39/src/bip39.dart';

main() async {
  String randomMnemonic = generateMnemonic();
  print(randomMnemonic);
  String seed = mnemonicToSeedHex(
      "update elbow source spin squeeze horror world become oak assist bomb nuclear");
  print(seed);
  String mnemonic = entropyToMnemonic('00000000000000000000000000000000');
  print(mnemonic);
  bool isValid = validateMnemonic(mnemonic);
  print(isValid);
  isValid = validateMnemonic('basket actual');
  print(isValid);
  String entropy = mnemonicToEntropy(mnemonic);
  print(entropy);
}
