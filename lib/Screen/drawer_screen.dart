import 'package:flutter/material.dart';
import '../Screen/wallet_screen.dart';
import '../Screen/about_screen.dart';
import '../Global/global.dart';
import '../Screen/profile_screen.dart';
import '../Splashscreen/splash_screen.dart';

class DrawerScreen extends StatelessWidget {
  const DrawerScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 220,
      child: Drawer(
        child: Padding(
          padding: EdgeInsets.fromLTRB(30, 50, 0, 20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              // Profile Section
              Row(
                children: [
                  Container(
                    padding: EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      Icons.person,
                      color: Colors.black,
                      size: 50,
                    ),
                  ),
                  SizedBox(width: 15),
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Text(
                      //   userModelCurrentInfo!.name!,
                      //   style: TextStyle(
                      //     fontWeight: FontWeight.bold,
                      //     fontSize: 20,
                      //   ),
                      // ),
                      SizedBox(height: 5),
                      GestureDetector(
                        onTap: () {
                          Navigator.push(context, MaterialPageRoute(builder: (c) => ProfileScreen()));
                        },
                        child: Text(
                          "Edit Profile",
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            fontSize: 14,
                            color: Colors.blue,
                          ),
                        ),
                      ),
                    ],
                  ),
                ],
              ),

              SizedBox(height: 20),

              // White Divider
              Divider(color: Colors.white),

              SizedBox(height: 20),

              // Wallet and My Hustler Section
              GestureDetector(
                onTap: () {
                  Navigator.push(context, MaterialPageRoute(builder: (c) => WalletScreen()));
                },
                child: Row(
                  children: [
                    Icon(Icons.wallet, color: Colors.white54),
                    SizedBox(width: 10),
                    Text(
                      "Wallet",
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                      ),
                    ),
                  ],
                ),
              ),

              SizedBox(height: 15),

              GestureDetector(
                // onTap: () {
                //   Navigator.push(context, MaterialPageRoute(builder: (c) => ProfileScreen()));
                // },
                child: Row(
                  children: [
                    Icon(Icons.person, color: Colors.white54), // Example icon
                    SizedBox(width: 10),
                    Text(
                      "My Hustler",
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                      ),
                    ),
                  ],
                ),
              ),

              SizedBox(height: 15),

              GestureDetector(
                onTap: () {
                  Navigator.push(context, MaterialPageRoute(builder: (c) => AboutScreen()));
                },
                child: Row(
                  children: [
                    Icon(Icons.info, color: Colors.white54),
                    SizedBox(width: 10),
                    Text(
                      "About",
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                      ),
                    ),
                  ],
                ),
              ),

              SizedBox(height: 20),

              // Another Divider
              Divider(color: Colors.white),

              SizedBox(height: 20),

              // Update and Logout with Icons
              GestureDetector(
                onTap: () {
                  Navigator.push(context, MaterialPageRoute(builder: (c) => ProfileScreen())); // Update action
                },
                child: Row(
                  children: [
                    Icon(Icons.update, color: Colors.white54), // Update icon
                    SizedBox(width: 10),
                    Text(
                      "Update",
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 15,
                      ),
                    ),
                  ],
                ),
              ),

              SizedBox(height: 15),

              GestureDetector(
                onTap: () {
                  firebaseAuth.signOut();
                  Navigator.push(context, MaterialPageRoute(builder: (c) => SplashScreen()));
                },
                child: Row(
                  children: [
                    Icon(Icons.logout, color: Colors.red), // Logout icon
                    SizedBox(width: 10),
                    Text(
                      "Logout",
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 18,
                        color: Colors.red,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
