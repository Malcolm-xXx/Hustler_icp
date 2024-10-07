import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:email_validator/email_validator.dart';
import 'package:fluttertoast/fluttertoast.dart';

import 'package:agent_dart/agent_dart.dart'; // ICP Agent Dart SDK

import '../FadeAnimation.dart';
import '../Global/global.dart';
import '../Screen/login_screen.dart';

class ForgetPasswordScreen extends StatefulWidget {
  const ForgetPasswordScreen({super.key});

  @override
  State<ForgetPasswordScreen> createState() => _ForgetPasswordScreenState();
}

class _ForgetPasswordScreenState extends State<ForgetPasswordScreen> {

  final emailTextEditingController = TextEditingController();

  final _formKey = GlobalKey<FormState>();

  // Function to send password reset using ICP
  Future<void> _resetPasswordWithICP() async {
    if (_formKey.currentState!.validate()) {
      try {
        // Initialize the ICP agent and actor
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

        // Call the password reset method on your ICP backend
        final result = await actor.resetPassword({
          'email': emailTextEditingController.text.trim(),
        });

        if (result['success']) {
          Fluttertoast.showToast(msg: "An email has been sent to recover your password. Please check your email.");
        } else {
          Fluttertoast.showToast(msg: "Error occurred: ${result['error']}");
        }
      } catch (error) {
        Fluttertoast.showToast(msg: "Error occurred: $error");
      }
    } else {
      Fluttertoast.showToast(msg: "Please enter a valid email.");
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
                    FadeAnimation(1, Text("Hustler", style: TextStyle(fontFamily:'font1', color: Colors.amber.shade400, fontSize: 50))),
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
                      FadeAnimation(1, Center(child: Text("Forget Password", style: TextStyle(color: darkTheme ? Color(0xFFF8F9FF) : Colors.white, fontSize: 40)))),
                      const SizedBox(height: 10,),
                      FadeAnimation(1.3, Center(child: Text("Don't get signed out", style: TextStyle(color: darkTheme ? Color(0xFFF8F9FF) : Colors.white, fontSize: 18)))),
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
                                FadeAnimation(2.5, TextFormField(
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
                                    prefixIcon: Icon(Icons.person, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                  ),
                                  autovalidateMode: AutovalidateMode.onUserInteraction,
                                  validator: (text) {
                                    if (text == null || text.isEmpty) {
                                      return "Email can't be empty";
                                    }
                                    if (!EmailValidator.validate(text)) {
                                      return "Please enter a valid email.";
                                    }
                                    return null;
                                  },
                                  onChanged: (text) => setState(() {
                                    emailTextEditingController.text = text;
                                  }),
                                )), // Email Field

                                const SizedBox(height: 20,),

                                ElevatedButton(
                                  onPressed: _resetPasswordWithICP,
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
                                    "Reset Password",
                                    style: TextStyle(fontSize: 20),
                                  ),
                                ), // Reset Button

                                const SizedBox(height: 20,),

                                Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Text(
                                      "Already have an account?",
                                      style: TextStyle(color: Colors.grey, fontSize: 12),
                                    ),
                                    const SizedBox(width: 5,),
                                    GestureDetector(
                                      onTap: () {
                                        Navigator.push(context, MaterialPageRoute(builder: (c) => const LoginScreen()));
                                      },
                                      child: Text(
                                        "Login",
                                        style: TextStyle(color: Colors.amber.shade400, fontSize: 15),
                                      ),
                                    ),
                                  ],
                                ), // Login Link
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ), // Form Container
            ],
          ),
        ),
      ),
    );
  }
}

