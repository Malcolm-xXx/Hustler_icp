import 'package:flutter/material.dart';
import 'package:hustleruser/cont/color.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart'; // Import the FontAwesome package

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key});

  // Method to open URLs
  Future<void> _launchUrl(String url) async {
    if (await canLaunch(url)) {
      await launch(url);
    } else {
      throw 'Could not launch $url';
    }
  }

  @override
  Widget build(BuildContext context) {
    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;

    return GestureDetector(
      onTap: () {
        FocusScope.of(context).unfocus();
      },
      child: Scaffold(
        backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),

        appBar: AppBar(

          title: Text(
            "About",
            style: TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
          ),

          backgroundColor: backgroundColors, // App bar color
          leading: IconButton(
            icon: Icon(Icons.arrow_back, color: Colors.white),
            onPressed: () {
              Navigator.pop(context);
            },
          ),
        ),

        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // App Information Section
              const Text(
                "Hustler is your go-to app for finding reliable individuals to run your daily errands. "
                    "Whether you need groceries, deliveries, or any other tasks completed, "
                    "connect with trusted hustlers and get your errands done effortlessly and efficiently.",
                style: TextStyle(fontSize: 14), // Reduced font size
              ),
              const SizedBox(height: 20),

              // Social Media Links Section
              const Text(
                "Follow Us",
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 10),

              // Social Media Icons and Names in Column
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      FaIcon(FontAwesomeIcons.facebook, color: Colors.blue),
                      const SizedBox(width: 10),
                      GestureDetector(
                        onTap: () => _launchUrl("https://www.facebook.com/your_page"),
                        child: const Text(
                          "Facebook",
                          style: TextStyle(fontSize: 14, color: Colors.white),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      FaIcon(FontAwesomeIcons.twitter, color: Colors.blueAccent),
                      const SizedBox(width: 10),
                      GestureDetector(
                        onTap: () => _launchUrl("https://twitter.com/your_page"),
                        child: const Text(
                          "Twitter",
                          style: TextStyle(fontSize: 14, color: Colors.white),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      FaIcon(FontAwesomeIcons.instagram, color: Colors.purple),
                      const SizedBox(width: 10),
                      GestureDetector(
                        onTap: () => _launchUrl("https://instagram.com/your_page"),
                        child: const Text(
                          "Instagram",
                          style: TextStyle(fontSize: 14, color: Colors.white),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              const SizedBox(height: 30),

              // Website link as text that navigates to website
              GestureDetector(
                onTap: () => _launchUrl("https://yourappwebsite.com"),
                child: const Text(
                  "Website",
                  style: TextStyle(
                    fontSize: 14, // Reduced font size
                    color: Colors.blueAccent,
                    decoration: TextDecoration.underline,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

