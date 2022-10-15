import 'package:bip39/bip39.dart' as bip39;
import 'package:fast_rsa/fast_rsa.dart';
import 'dart:math';
import 'package:ninja_prime/ninja_prime.dart';

class SeededRandom {
  late String digest;
  SeededRandom(String mnemonic) {
    if(bip39.validateMnemonic(mnemonic)){
      digest = bip39.mnemonicToSeedHex(mnemonic);
    } else {
      digest = mnemonic;
    }
  }

  Future<void> basedDerivation() async {
    await _derivation(2048);
  }

  Future<void> _derivation(int left) async {
    if(left > 0){
      digest = await RSA.hash(digest, Hash.SHA512);
      await _derivation(left-1);
    }
  }

  double logBase(num x, num base) => log(x) / log(base);
  double log2(num x) => logBase(x, 2);

  int getKeySizeInDecimal(int keysize) => -(-(keysize * log(2)/log(10))).floor();

  BigInt _getNextBigInt(int size) {
    var bigIntStr = digest.codeUnits.join();
    while(bigIntStr.length < size){
      _derivation(1);
      bigIntStr += digest.codeUnits.join();
    }

    bigIntStr = bigIntStr.substring(0,size);
    return BigInt.parse(bigIntStr);
  }

  BigInt randomPrimeBigInt(int keysize){
    int size = getKeySizeInDecimal(keysize);
    var bi = _getNextBigInt(size);

    while(!bi.isPrime()){
      bi = _getNextBigInt(size);
    }
    return bi;
  }
}
