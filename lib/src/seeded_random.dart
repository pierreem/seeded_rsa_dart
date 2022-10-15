import 'package:crypto/crypto.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'dart:math';
import 'package:ninja_prime/ninja_prime.dart';

class SeededRandom {
  late Digest digest;
  SeededRandom(String mnemonic) {
    if(bip39.validateMnemonic(mnemonic)){
      digest = sha512.convert(bip39.mnemonicToSeed(mnemonic));
    } else {
      digest = sha512.convert(mnemonic.codeUnits);
    }

    //based derivations
    for(var i = 0 ; i < 2048; i++) {
      digest = sha512.convert(digest.bytes);
    }
  }

  double logBase(num x, num base) => log(x) / log(base);
  double log2(num x) => logBase(x, 2);

  int getKeySizeInDecimal(int keysize) => -(-(keysize * log(2)/log(10))).floor();

  BigInt _getNextBigInt(int size) {
    var bigIntStr = digest.bytes.join();
    while(bigIntStr.length < size){
      digest = sha512.convert(digest.bytes);
      bigIntStr += digest.bytes.join();
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
