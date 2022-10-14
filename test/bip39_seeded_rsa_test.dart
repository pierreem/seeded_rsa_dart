import 'package:bip39_seeded_rsa/bip39_seeded_rsa.dart';
//import 'package:test/test.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:ninja_prime/ninja_prime.dart';

import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'dart:math';

void main() async {
  String mnemonnic = "wash list guard stool slogan lift boss imitate story trash put option";
  //bip39.generateMnemonic();
  final awesome = RSAKey(mnemonnic);

  //print(SeededRandom(mnemonnic).randomPrimeBigInt(2048));
  print(await awesome.generate());


}
