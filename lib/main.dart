import 'package:flutter/material.dart';
import 'package:agent_dart/agent_dart.dart'; // Import the agent_dart package
import 'package:provider/provider.dart';
import '../Themeprovider/theme_provider.dart';
import '../infoHandler/app_info.dart';
import '../Splashscreen/splash_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the ICP agent here instead of Firebase
  final agent = HttpAgent(
    options: HttpAgentOptions(
      url: 'http://127.0.0.1:4943/?canisterId=bd3sg-teaaa-aaaaa-qaaba-cai&id=bkyz2-fmaaa-aaaaa-qaaaq-cai',
    ),
  );

  // Fetch the root key for ICP (necessary for local development only)
  // You can comment this line out when deploying to production
  await agent.fetchRootKey();

  runApp(MyApp(agent: agent)); // Pass the agent to the app
}

class MyApp extends StatelessWidget {
  final HttpAgent agent; // Pass the agent to the app

  const MyApp({super.key, required this.agent});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (context) => AppInfo(),
      child: MaterialApp(
        title: 'Hustler',
        themeMode: ThemeMode.system,
        theme: MyThemes.lightTheme,
        darkTheme: MyThemes.darkTheme,
        debugShowCheckedModeBanner: false,
        home: SplashScreen(), // Pass the agent to SplashScreen
      ),
    );
  }
}

