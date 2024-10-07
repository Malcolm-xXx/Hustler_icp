import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:email_validator/email_validator.dart';
import 'package:fluttertoast/fluttertoast.dart';

import 'package:agent_dart/agent_dart.dart'; // ICP Agent Dart SDK
import '../FadeAnimation.dart';
import '../Global/global.dart';
import '../Screen/main_screen.dart';
import '../Screen/forgot_password_screen.dart';
import '../Screen/registration_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});

  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {

  final emailTextEditingController = TextEditingController();
  final passwordTextEditingController = TextEditingController();

  bool _passwordVisible = false;

  final _formKey = GlobalKey<FormState>();

  // Function to login using ICP
  Future<void> _loginWithICP() async {
    if (_formKey.currentState!.validate()) {
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

        // Call login method on your ICP backend
        final result = await actor.login({
          'email': emailTextEditingController.text.trim(),
          'password': passwordTextEditingController.text.trim(),
        });

        if (result['success']) {
          currentUser = result['user']; // Assign the currentUser from ICP response

          Fluttertoast.showToast(msg: "Successfully logged in");
          Navigator.push(context, MaterialPageRoute(builder: (c) => const MainScreen()));
        } else {
          Fluttertoast.showToast(msg: "Login failed: ${result['error']}");
        }
      } catch (error) {
        Fluttertoast.showToast(msg: "Error occurred: $error");
      }
    } else {
      Fluttertoast.showToast(msg: "Not all fields are valid");
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
        body: Container(
          width: double.infinity,
          decoration: const BoxDecoration(
            color: Color(0xFF464C64),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 80,),

              Center(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: <Widget>[
                    FadeAnimation(1,
                      Text("Hustler", style: TextStyle(fontFamily: 'font1', color: Colors.amber.shade400, fontSize: 50)),
                    ),
                  ],
                ),
              ),

              const SizedBox(height: 10,),

              Padding(
                padding: const EdgeInsets.all(20),
                child: Center(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      FadeAnimation(1, Text("Login", style: TextStyle(color: darkTheme ? Color(0xFFF8F9FF) : Colors.white, fontSize: 40))),
                      const SizedBox(height: 10,),
                      FadeAnimation(1.3, Text("Welcome back", style: TextStyle(color: darkTheme ? Color(0xFFF8F9FF) : Colors.white, fontSize: 18))),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 20),

              Expanded(
                child: Container(
                  decoration: BoxDecoration(
                    color: darkTheme ? Color(0xFFF1B1A28) : Colors.white,
                    borderRadius: const BorderRadius.only(topLeft: Radius.circular(60), topRight: Radius.circular(60)),
                  ),
                  child: SingleChildScrollView(
                    child: Padding(
                      padding: const EdgeInsets.all(30),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          Form(
                            key: _formKey,
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              crossAxisAlignment: CrossAxisAlignment.center,
                              children: [
                                const SizedBox(height: 10,),

                                FadeAnimation(2.5,
                                  TextFormField(
                                    inputFormatters: [
                                      LengthLimitingTextInputFormatter(100),
                                    ],
                                    decoration: InputDecoration(
                                      hintText: 'Email',
                                      hintStyle: const TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: const BorderSide(width: 0, style: BorderStyle.none),
                                      ),
                                      prefixIcon: Icon(Icons.email, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                    ),
                                    autovalidateMode: AutovalidateMode.onUserInteraction,
                                    validator: (text) {
                                      if (text == null || text.isEmpty) {
                                        return "Email can't be empty";
                                      }
                                      if (!EmailValidator.validate(text)) {
                                        return "Please enter a valid email";
                                      }
                                      if (text.length > 99) {
                                        return "Email can't be more than 100";
                                      }
                                      return null;
                                    },
                                    onChanged: (text) => setState(() {
                                      emailTextEditingController.text = text;
                                    }),
                                  ),
                                ), // Email

                                const SizedBox(height: 20,),

                                FadeAnimation(2.7,
                                  TextFormField(
                                    obscureText: !_passwordVisible,
                                    inputFormatters: [
                                      LengthLimitingTextInputFormatter(50),
                                    ],
                                    decoration: InputDecoration(
                                      hintText: 'Password',
                                      hintStyle: const TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: const BorderSide(width: 0, style: BorderStyle.none),
                                      ),
                                      prefixIcon: Icon(Icons.person, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                      suffixIcon: IconButton(
                                        icon: Icon(_passwordVisible ? Icons.visibility : Icons.visibility_off,
                                          color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey,
                                        ),
                                        onPressed: () => setState(() {
                                          _passwordVisible = !_passwordVisible;
                                        }),
                                      ),
                                    ),
                                    autovalidateMode: AutovalidateMode.onUserInteraction,
                                    validator: (text) {
                                      if (text == null || text.isEmpty) {
                                        return "Password can't be empty";
                                      }
                                      if (text.length < 8) {
                                        return "Password must be at least 8 characters";
                                      }
                                      if (text.length > 49) {
                                        return "Password can't be more than 50";
                                      }
                                      return null;
                                    },
                                    onChanged: (text) => setState(() {
                                      passwordTextEditingController.text = text;
                                    }),
                                  ),
                                ), // Password

                                const SizedBox(height: 20,),

                                ElevatedButton(
                                  onPressed: () {
                                    _loginWithICP();
                                  },
                                  style: ElevatedButton.styleFrom(
                                    primary: Colors.amber.shade400,
                                    onPrimary: darkTheme ? Colors.black : Colors.white,
                                    elevation: 10,
                                    shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(32),
                                    ),
                                    minimumSize: const Size(double.infinity, 50),
                                  ),
                                  child: const Text(
                                    "Login",
                                    style: TextStyle(fontSize: 20),
                                  ),
                                ), // Login button

                                const SizedBox(height: 20,),

                                GestureDetector(
                                  onTap: () {
                                    Navigator.push(context, MaterialPageRoute(builder: (c) => const ForgetPasswordScreen()));
                                  },
                                  child: Text(
                                    "Forgot password?",
                                    style: TextStyle(color: Colors.amber.shade400),
                                  ),
                                ), // Forgot Password

                                const SizedBox(height: 20,),

                                Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Text(
                                      "I don't have an account?",
                                      style: TextStyle(color: Colors.grey, fontSize: 12),
                                    ),
                                    const SizedBox(width: 5,),
                                    GestureDetector(
                                      onTap: () {
                                        Navigator.push(context, MaterialPageRoute(builder: (c) => const RegistrationScreen()));
                                      },
                                      child: Text(
                                        "Sign up",
                                        style: TextStyle(color: Colors.amber.shade400, fontSize: 15),
                                      ),
                                    ),
                                  ],
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ), // Form
            ],
          ),
        ),
      ),
    );
  }
}



