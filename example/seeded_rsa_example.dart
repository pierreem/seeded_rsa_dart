import 'package:seeded_rsa/seeded_rsa.dart';

Future<void> main() async {
  String mnemonnic = "track steel battle rookie speak mystery uncover rebel basic lounge cloud enact";
  final seededRSA = SeededRSA(mnemonnic);

  print(await seededRSA.generate());

}
