import 'package:flutter/material.dart';
import 'dart:async';
import 'package:agent_dart/agent_dart.dart';
import '../FadeAnimation.dart';
import '../Global/global.dart';
import '../Assistance/assistance_method.dart';
import '../Onboarding/onboarding_view.dart';
import '../Screen/main_screen.dart';
import '../Screen/login_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({Key? key}) : super(key: key);

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {

  @override
  void initState() {
    super.initState();
    startTimer();
  }

  startTimer() {
    Timer(Duration(seconds: 3), () async {
      try {
        // Fetch user data from ICP
        bool isLoggedIn = await checkIfUserIsLoggedInOnICP();
        if (isLoggedIn) {
          AssistanceMethods.readCurrentOnlineUserInfo();
          Navigator.pushReplacement(
              context,
              MaterialPageRoute(builder: (c) => MainScreen())
          );
        } else {
          Navigator.pushReplacement(
              context,
              MaterialPageRoute(builder: (c) => OnboardingView())
          );
        }
      } catch (e) {
        print("Error during login check: $e");
        Navigator.pushReplacement(
            context,
            MaterialPageRoute(builder: (c) => OnboardingView())
        );
      }
    });
  }

  // Function to check if the user is logged in via ICP
  Future<bool> checkIfUserIsLoggedInOnICP() async {
    try {
      final agent = HttpAgent(options: HttpAgentOptions(host: 'http://127.0.0.1:4943'));
      await agent.fetchRootKey();

      final canisterId = Principal.fromText('bd3sg-teaaa-aaaaa-qaaba-cai&id=bkyz2-fmaaa-aaaaa-qaaaq-cai');
      final actor = Actor.createActor(
        ActorInterfaceFactory.fromIDL(), // Define IDL factory for your canister
        ActorConfig(
          canisterId: canisterId,
          agent: agent,
        ),
      );

      final result = await actor.call<bool>('isUserLoggedIn');
      return result;
    } catch (e) {
      print("Error checking user login status on ICP: $e");
      return false;
    }
  }

  @override
  Widget build(BuildContext context) {
    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;
    return Container(
      decoration: BoxDecoration(
        color: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
      ),
      child: Scaffold(
        backgroundColor: Colors.transparent,
        body: Center(
          child: FadeAnimation(
              1,
              Text(
                "Hustler",
                style: TextStyle(
                  fontFamily: 'font1',
                  color: Colors.amber.shade400,
                  fontSize: 80,
                ),
              )
          ),
        ),
      ),
    );
  }
}
