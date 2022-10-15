import 'dart:convert';
import 'dart:typed_data';
import 'package:ninja_prime/ninja_prime.dart';
import 'package:ninja_asn1/ninja_asn1.dart';
import 'package:seeded_rsa/src/seeded_random.dart';

class SeededRSA {
  static const int PEM_CHAR_LINE_SIZE = 64;
  late BigInt n, d, p, q, dmp1, dmq1, coeff, e = BigInt.zero;
  late String seed;

  SeededRSA(this.seed);

  String _toPem(String pkeyb64, {String key = "RSA PRIVATE KEY"}){
    String pemString = "-----BEGIN $key-----\n";
    for(var i = 0; i < pkeyb64.length; i+=PEM_CHAR_LINE_SIZE) {
      var i64 = i+PEM_CHAR_LINE_SIZE;
      if(i64 > pkeyb64.length) i64 = pkeyb64.length;
      pemString+="${pkeyb64.substring(i, i64)}\n";
    }
    pemString += "-----END $key-----";
    return pemString;
  }

   String privateKey() {
    final original = ASN1Sequence(
      [
      ASN1Integer(BigInt.zero),
      ASN1Integer(n),
      ASN1Integer(e),
      ASN1Integer(d),
      ASN1Integer(p),
      ASN1Integer(q),
      ASN1Integer(dmp1),
      ASN1Integer(dmq1),
      ASN1Integer(coeff)
      ]
    );
    return _toPem(base64Encode(original.encode()));
  }

  String publicBaseKey() {
    var secondSequence = ASN1Sequence(
      [
        ASN1Integer(n),
        ASN1Integer(e)
      ]
      );

    String sq =  "00${base64Encode(secondSequence.encode())}";
    var seq = ASN1Sequence(
      [
        ASN1ObjectIdentifier.fromString('1.2.840.113549.1.1.1'),
        ASN1Null(),
        ASN1BitString(Uint8List.fromList(sq.codeUnits))
      ]
      );

    return _toPem(base64Encode(seq.encode()), key: "RSA PUBLIC KEY");
  }


  Future<Map<String,String>> generate({int keySize = 2048, String exposant = "65537"}) async {
    var seededRandom = SeededRandom(seed);
    var qs = keySize >> 1;
    e = BigInt.parse(exposant,radix: 16);
    var exponent = BigInt.parse(exposant, radix: 16);

    var valid = false;

    while(!valid) {
        try{
          p = seededRandom.randomPrimeBigInt(keySize-qs);
          q = seededRandom.randomPrimeBigInt(qs);
          if(p < q){
            var t = p;
            p = q;
            q = p;
          }

          var p1 = p - BigInt.one;
          var q1 = q - BigInt.one;
          var phi = p1 * q1;
          if(phi.gcd(exponent) == BigInt.one){
            n = p * q;
            d = exponent.modInverse(phi);
            dmp1 = d % p1;
            dmq1 = d % q1;
            coeff = q.modInverse(p);
            valid = true;
          }
        } catch(e){
          valid = false;
        }
    }

    var key = {
      'privateKey': privateKey(),
      'publicKey': publicBaseKey()
    };

    return key;
  }


}
