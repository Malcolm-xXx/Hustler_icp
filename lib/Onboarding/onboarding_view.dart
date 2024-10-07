import 'package:flutter/material.dart';


import '../FadeAnimation.dart';
import '../Onboarding/onboarding_items.dart';
import '../Screen/login_screen.dart';
import '../Screen/registration_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:smooth_page_indicator/smooth_page_indicator.dart';

class OnboardingView extends StatefulWidget {
  const OnboardingView({super.key});

  @override
  State<OnboardingView> createState() => _OnboardingViewState();
}

class _OnboardingViewState extends State<OnboardingView> {
  final controller = OnboardingItems();
  final pageController = PageController();
  int currentPage = 0; // Track the current page

  @override
  Widget build(BuildContext context) {
    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;
    return Scaffold(
      backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64), // Set the background color
      appBar: PreferredSize(
        preferredSize: const Size.fromHeight(60), // Set the height of the custom app bar
        child: Container(
          color: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
          child: FadeAnimation(1.3, buildTopNavigation()),
        ),
      ),

      body: Container(
        margin: const EdgeInsets.symmetric(horizontal: 15),
        child: PageView.builder(
          controller: pageController,
          itemCount: controller.items.length,
          onPageChanged: (index) {
            setState(() {
              currentPage = index;
            });
          },
          itemBuilder: (context, index) {
            return Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Expanded(
                  child: Center(
                    child: Image.asset(controller.items[index].image),
                  ),
                ),
                Expanded(
                  child: Center(
                    child: FadeAnimation(1.3,
                      Text(
                        controller.items[index].descriptions,
                        style: const TextStyle(color: Colors.grey, fontSize: 17),
                        textAlign: TextAlign.center,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 15),
              ],
            );
          },
        ),
      ),

      bottomSheet: Container(
        color: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 40),
        child: FadeAnimation(1.3, buildBottomNavigation()),
      ),

    );
  }

  Widget buildTopNavigation() {
    if (currentPage == controller.items.length - 1) {
      // Last Page - Show "Get Started"
      return Row(
        mainAxisAlignment: MainAxisAlignment.start,
        children: [
          TextButton(
            onPressed: () => pageController.previousPage(
              duration: const Duration(milliseconds: 600),
              curve: Curves.easeIn,
            ),
            style: TextButton.styleFrom(
              primary: Color(0xFF767E9E), // Color for "Prev"
            ),
            child: const Text("Prev"),
          ),
        ],
      );
    } else if (currentPage == 0) {
      // First Page - Show "Skip"
      return Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [

          TextButton(
            onPressed: () => pageController.animateToPage(
              controller.items.length - 1,
              duration: Duration(milliseconds: 500),
              curve: Curves.easeInOut,
            ),
            style: TextButton.styleFrom(
              primary: Color(0xFF767E9E),
            ),
            child: const Text("Skip"),
          ),
        ],
      );
    } else {
      // Middle Pages - Show "Skip" and "Prev"
      return Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          TextButton(
            onPressed: () => pageController.previousPage(
              duration: const Duration(milliseconds: 600),
              curve: Curves.easeIn,
            ),
            style: TextButton.styleFrom(
              primary: Color(0xFF767E9E), // Color for "Prev"
            ),
            child: const Text("Prev"),
          ),


          TextButton(
            onPressed: () => pageController.animateToPage(
              controller.items.length - 1,
              duration: Duration(milliseconds: 500),
              curve: Curves.easeInOut,
            ),
            style: TextButton.styleFrom(
              primary: Color(0xFF767E9E),
            ),
            child: const Text("Skip"),
          ),
        ],
      );
    }
  }

  Widget buildBottomNavigation() {
    if (currentPage == controller.items.length - 1) {
      // Last Page - Show "Get Started"
      return Row(
        mainAxisAlignment: MainAxisAlignment.spaceAround,
        children: [
          TextButton(
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => LoginScreen()), // Navigate to login page
              );
            },
            style: TextButton.styleFrom(
              primary: Color(0xFFF8F9FF), // Color for "Login"
            ).copyWith(
               textStyle: MaterialStateProperty.all(
                const TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
            child: const Text("Login"),
          ),
          SizedBox(
            width: 125,
            height: 50,
            child: getStarted(),
          ),
        ],
      );
    } else {
      // Middle Pages - Show "Skip" and "Prev"
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Center(
            child: SmoothPageIndicator(
              controller: pageController,
              count: controller.items.length,
              onDotClicked: (index) => pageController.animateToPage(
                index,
                duration: const Duration(milliseconds: 600),
                curve: Curves.easeIn,
              ),
              effect: const WormEffect(
                dotHeight: 12,
                dotWidth: 12,
                activeDotColor: Color(0xFFFFCB2A), // Color for active dot
              ),
            ),
          ),
          const SizedBox(height: 20), // Optional spacing
        ],
      );
    }
  }

  // Get started button
  Widget getStarted() {
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(50),
        color: Colors.amber.shade400, // Color for "Get Started"
      ),
      child: TextButton(
        onPressed: () async {
          final prefs = await SharedPreferences.getInstance();
          prefs.setBool("onboarding", true);

          // After we press get started button, this onboarding value becomes true
          if (!mounted) return;
          Navigator.pushReplacement(
            context,
            MaterialPageRoute(builder: (context) => RegistrationScreen()),
          );
        },
        child: const Text(
          "Get started",
          style: TextStyle(color: Colors.black, fontSize: 16,
            fontWeight: FontWeight.w700,),
        ),
      ),
    );
  }



}