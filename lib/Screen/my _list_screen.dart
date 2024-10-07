import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

import '../Global/firestor.dart';
import '../Model/add_list.dart';
import '../Model/user_model.dart';
import '../Screen/get_hustler_screen.dart';

import '../Widget/stream_note.dart';


class MyListScreen extends StatefulWidget {
  const MyListScreen({super.key});

  @override
  State<MyListScreen> createState() => _MyListScreenState();
}

class _MyListScreenState extends State<MyListScreen> {
  bool show = true;
  ValueNotifier<double> totalPriceNotifier = ValueNotifier(0.0); // Use ValueNotifier to track total price
  List<Note> allNotes = [];
  // // Callback to update the total price
  // void updateTotalPrice(double price) {
  //   setState(() {
  //     totalPrice = price;
  //   });
  // }

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
          backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
          title: Text(
            "My List",
            style: TextStyle(
              color: Colors.white,
              fontWeight: FontWeight.bold,
              fontSize: 18,
            ),
          ),
          leading: IconButton(
            icon: Icon(Icons.arrow_back, color: Colors.white),
            onPressed: () {
              Navigator.pop(context);
            },
          ),
          actions: [
            IconButton(
              icon: Icon(Icons.add, color: Colors.white),
              onPressed: () {
                Navigator.of(context).push(MaterialPageRoute(
                  builder: (context) => AddList(),
                ));
              },
            ),
          ],
        ),

        body: SafeArea(
          child: Column(
            children: [
              Expanded(
                child: NotificationListener<UserScrollNotification>(
                  onNotification: (notification) {
                    if (notification.direction == ScrollDirection.forward) {
                      setState(() {
                        show = true;
                      });
                    } else if (notification.direction == ScrollDirection.reverse) {
                      setState(() {
                        show = false;
                      });
                    }
                    return true;
                  },
                  child: ListView(
                    children: [

                      Stream_note(
                        false, // or true depending on the condition
                        totalPriceNotifier: totalPriceNotifier, // Assuming this is defined
                        onNotesUpdated: (List<Note> updatedNotes) {
                          setState(() {
                            allNotes = updatedNotes; // Store updated notes in the parent widget
                          });
                        },
                      ),

                      Stream_note(
                        true, // or true depending on the condition
                        totalPriceNotifier: totalPriceNotifier, // Assuming this is defined
                        onNotesUpdated: (List<Note> updatedNotes) {
                          setState(() {
                            allNotes = updatedNotes; // Store updated notes in the parent widget
                          });
                        },
                      ),
                      // Stream_note(
                      //   false,
                      //   totalPriceNotifier: totalPriceNotifier,
                      //   onNotesUpdated: (notes) {
                      //     setState(() {
                      //       allNotes = notes; // Update the list of all notes
                      //     });
                      //   },
                      // ),
                      // Stream_note(
                      //   true,
                      //   totalPriceNotifier: totalPriceNotifier,
                      //   onNotesUpdated: (notes) {
                      //     setState(() {
                      //       allNotes = notes; // Update the list of all notes
                      //     });
                      //   },
                      // ),
                    ],
                  ),
                ),
              ),
              ValueListenableBuilder<double>(
                valueListenable: totalPriceNotifier, // Listen to changes in totalPriceNotifier
                builder: (context, totalPrice, child) {
                  return Container(
                    color: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
                    padding:EdgeInsets.fromLTRB(50, 5, 50, 15),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          "Total Price:",
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          "₦$totalPrice", // Display the total price from ValueNotifier
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  );
                },
              ),
              Container(
                padding: const EdgeInsets.fromLTRB(50, 5, 50, 200),
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    primary: Colors.amber.shade400, // Amber background color
                    minimumSize: Size(double.infinity, 50), // Full width and fixed height
                    elevation: 10,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(32),
                    ),
                  ),
                  onPressed: () {
                    if (allNotes.isNotEmpty) {
                      // Send the items to the vendor-side list
                      sendItemsToVendor(allNotes);
                    } else {
                      // Show a message if there are no items
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('No items to send')),
                      );
                    }
                  },
                  child: Text(
                    'Find My Hustler',
                    style: TextStyle(
                      color: Colors.black, // Black text color
                      fontWeight: FontWeight.bold,
                      fontSize: 16,
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


  // Method to send items to vendor-side list
  void sendItemsToVendor(List<Note> notes) {
    // Implement the logic to send the notes to the vendor-side list
    Firestore_Datasource().sendNotesToVendor(notes);

    // Navigate to the vendor-side screen (replace GetHustlerScreen with your screen)
    Navigator.of(context).push(MaterialPageRoute(
      builder: (context) => GetHustlerScreen(),
    ));
  }
}