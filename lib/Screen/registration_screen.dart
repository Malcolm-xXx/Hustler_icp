import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:email_validator/email_validator.dart';
import 'package:intl_phone_field/intl_phone_field.dart';
import 'package:fluttertoast/fluttertoast.dart';
import 'package:agent_dart/agent_dart.dart';

import '../FadeAnimation.dart';
import '../Screen/login_screen.dart';
import '../Screen/main_screen.dart';

class RegistrationScreen extends StatefulWidget {
  const RegistrationScreen({super.key});

  @override
  State<RegistrationScreen> createState() => _RegistrationScreenState();
}

class _RegistrationScreenState extends State<RegistrationScreen> {
  final nameTextEditingController = TextEditingController();
  final emailTextEditingController = TextEditingController();
  final phoneTextEditingController = TextEditingController();
  final passwordTextEditingController = TextEditingController();
  final confirmTextEditingController = TextEditingController();

  bool _passwordVisible = false;

  final _formKey = GlobalKey<FormState>();

  void _submit() async {
    if (_formKey.currentState!.validate()) {
      await registerUserOnICP(emailTextEditingController.text.trim()).then((result) async {
        if (result) {
          await Fluttertoast.showToast(msg: "Successfully Registered");
          Navigator.pushReplacement(context, MaterialPageRoute(builder: (c) => MainScreen()));
        } else {
          Fluttertoast.showToast(msg: "User registration failed");
        }
      }).catchError((errorMessage) {
        Fluttertoast.showToast(msg: "Error occurred \n $errorMessage");
      });
    } else {
      Fluttertoast.showToast(msg: "Not all fields are valid");
    }
  }

  void registerUserOnICP(String username) async {
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

      final result = await actor.call('registerUser', [username]);
      print('User registration result: $result');
      return result;
    } catch (e) {
      print("Error registering user on ICP: $e");
      throw e;
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
          decoration: BoxDecoration(
            color: Color(0xFF464C64),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(height: 80),
              Center(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: <Widget>[
                    FadeAnimation(
                      1,
                      Text(
                        "Hustler",
                        style: TextStyle(fontFamily: 'font1', color: Colors.amber.shade400, fontSize: 50),
                      ),
                    ),
                  ],
                ),
              ),
              SizedBox(height: 10),
              Padding(
                padding: EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: <Widget>[
                    FadeAnimation(
                      1,
                      Text(
                        "Sign up",
                        style: TextStyle(color: darkTheme ? Color(0xFFF8F9FF) : Colors.white, fontSize: 40),
                      ),
                    ),
                    SizedBox(height: 10),
                    FadeAnimation(
                      1.3,
                      Text(
                        "Welcome ",
                        style: TextStyle(color: darkTheme ? Color(0xFFF8F9FF) : Colors.white, fontSize: 18),
                      ),
                    ),
                  ],
                ),
              ),
              SizedBox(height: 20),
              Expanded(
                child: Container(
                  decoration: BoxDecoration(
                    color: darkTheme ? Color(0xFFF1B1A28) : Colors.white,
                    borderRadius: BorderRadius.only(topLeft: Radius.circular(60), topRight: Radius.circular(60)),
                  ),
                  child: SingleChildScrollView(
                    child: Padding(
                      padding: EdgeInsets.all(30),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          Form(
                            key: _formKey,
                            child: Column(
                              mainAxisAlignment: MainAxisAlignment.center,
                              crossAxisAlignment: CrossAxisAlignment.center,
                              children: [
                                SizedBox(height: 10),
                                FadeAnimation(
                                  2.4,
                                  TextFormField(
                                    inputFormatters: [LengthLimitingTextInputFormatter(50)],
                                    decoration: InputDecoration(
                                      hintText: 'Name',
                                      hintStyle: TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: BorderSide(
                                          width: 0,
                                          style: BorderStyle.none,
                                        ),
                                      ),
                                      prefixIcon: Icon(Icons.person, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                    ),
                                    autovalidateMode: AutovalidateMode.onUserInteraction,
                                    validator: (text) {
                                      if (text == null || text.isEmpty) {
                                        return "Name can't be empty";
                                      }
                                      if (text.length < 2) {
                                        return "Please enter a valid name";
                                      }
                                      if (text.length > 49) {
                                        return "Name can't be more than 50 ";
                                      }
                                    },
                                    onChanged: (text) => setState(() {
                                      nameTextEditingController.text = text;
                                    }),
                                  ),
                                ), //name
                                SizedBox(height: 20),
                                FadeAnimation(
                                  2.5,
                                  TextFormField(
                                    inputFormatters: [LengthLimitingTextInputFormatter(100)],
                                    decoration: InputDecoration(
                                      hintText: 'Email',
                                      hintStyle: TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: BorderSide(
                                          width: 0,
                                          style: BorderStyle.none,
                                        ),
                                      ),
                                      prefixIcon: Icon(Icons.email, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                    ),
                                    autovalidateMode: AutovalidateMode.onUserInteraction,
                                    validator: (text) {
                                      if (text == null || text.isEmpty) {
                                        return "Email can't be empty";
                                      }
                                      if (EmailValidator.validate(text) == true) {
                                        return null;
                                      }
                                      if (text.length < 2) {
                                        return "Please enter a valid Email";
                                      }
                                      if (text.length > 99) {
                                        return "Email can't be more than 100 ";
                                      }
                                    },
                                    onChanged: (text) => setState(() {
                                      emailTextEditingController.text = text;
                                    }),
                                  ),
                                ), //email
                                SizedBox(height: 20),
                                FadeAnimation(
                                  2.6,
                                  IntlPhoneField(
                                    showCountryFlag: true,
                                    dropdownIcon: Icon(
                                      Icons.arrow_drop_down,
                                      color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey,
                                    ),
                                    decoration: InputDecoration(
                                      hintText: 'Phone',
                                      hintStyle: TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: BorderSide(
                                          width: 0,
                                          style: BorderStyle.none,
                                        ),
                                      ),
                                    ),
                                    initialCountryCode: 'NG',
                                    onChanged: (text) => setState(() {
                                      phoneTextEditingController.text = text.completeNumber;
                                    }),
                                  ),
                                ), // phone
                                SizedBox(height: 10),
                                FadeAnimation(
                                  2.7,
                                  TextFormField(
                                    obscureText: !_passwordVisible,
                                    inputFormatters: [LengthLimitingTextInputFormatter(50)],
                                    decoration: InputDecoration(
                                      hintText: 'Password',
                                      hintStyle: TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: BorderSide(
                                          width: 0,
                                          style: BorderStyle.none,
                                        ),
                                      ),
                                      prefixIcon: Icon(Icons.lock, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                      suffixIcon: IconButton(
                                        icon: Icon(
                                          _passwordVisible ? Icons.visibility : Icons.visibility_off,
                                          color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey,
                                        ),
                                        onPressed: () {
                                          setState(() {
                                            _passwordVisible = !_passwordVisible;
                                          });
                                        },
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
                                        return "Password can't be more than 50 ";
                                      }
                                    },
                                    onChanged: (text) => setState(() {
                                      passwordTextEditingController.text = text;
                                    }),
                                  ),
                                ), // password
                                SizedBox(height: 20),
                                FadeAnimation(
                                  2.8,
                                  TextFormField(
                                    obscureText: !_passwordVisible,
                                    inputFormatters: [LengthLimitingTextInputFormatter(50)],
                                    decoration: InputDecoration(
                                      hintText: 'Confirm Password',
                                      hintStyle: TextStyle(color: Color(0xFFF8F9FF)),
                                      filled: true,
                                      fillColor: darkTheme ? Color(0xFF464C64) : Colors.grey.shade200,
                                      border: OutlineInputBorder(
                                        borderRadius: BorderRadius.circular(40),
                                        borderSide: BorderSide(
                                          width: 0,
                                          style: BorderStyle.none,
                                        ),
                                      ),
                                      prefixIcon: Icon(Icons.lock, color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey),
                                      suffixIcon: IconButton(
                                        icon: Icon(
                                          _passwordVisible ? Icons.visibility : Icons.visibility_off,
                                          color: darkTheme ? Color(0xFFF8F9FF) : Colors.grey,
                                        ),
                                        onPressed: () {
                                          setState(() {
                                            _passwordVisible = !_passwordVisible;
                                          });
                                        },
                                      ),
                                    ),
                                    autovalidateMode: AutovalidateMode.onUserInteraction,
                                    validator: (text) {
                                      if (text == null || text.isEmpty) {
                                        return "Password can't be empty";
                                      }
                                      if (passwordTextEditingController.text != text) {
                                        return "Passwords don't match";
                                      }
                                      if (text.length < 8) {
                                        return "Password must be at least 8 characters";
                                      }
                                      if (text.length > 49) {
                                        return "Password can't be more than 50 ";
                                      }
                                    },
                                    onChanged: (text) => setState(() {
                                      confirmTextEditingController.text = text;
                                    }),
                                  ),
                                ), // confirm password
                              ],
                            ),
                          ),
                          SizedBox(height: 20),
                          FadeAnimation(
                            3.2,
                            ElevatedButton(
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.amber.shade400,
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(40),
                                ),
                              ),
                              onPressed: () {
                                _submit();
                              },
                              child: Padding(
                                padding: EdgeInsets.all(10),
                                child: Text(
                                  "Submit",
                                  style: TextStyle(
                                    color: Colors.black,
                                    fontSize: 20,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                            ),
                          ),
                          Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Text(
                                "Already have an account?",
                                style: TextStyle(color: Colors.grey),
                              ),
                              TextButton(
                                onPressed: () {
                                  Navigator.pushReplacement(context, MaterialPageRoute(builder: (c) => LoginScreen()));
                                },
                                child: Text(
                                  "Login Here",
                                  style: TextStyle(color: Colors.black54),
                                ),
                              ),
                            ],
                          ),
                          SizedBox(height: 30),
                        ],
                      ),
                    ),
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
