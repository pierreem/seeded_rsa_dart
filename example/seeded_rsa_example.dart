import 'package:seeded_rsa/seeded_rsa.dart';

Future<void> main() async {
  String mnemonnic = "wash list guard stool slogan lift boss imitate story trash put option";
  final seededRSA = SeededRSA(mnemonnic);

  print(await seededRSA.generate());

}
