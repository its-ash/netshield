import 'package:flutter/material.dart';
import 'package:theme/theme.dart';

import 'screens/home_screen.dart';
import 'shield/shield_store.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(NetShieldApp(store: ShieldStore()));
}

class NetShieldApp extends StatelessWidget {
  const NetShieldApp({super.key, required this.store});

  final ShieldStore store;

  @override
  Widget build(BuildContext context) {
    return UiApp(
      title: 'NetShield',
      home: HomeScreen(store: store),
    );
  }
}
