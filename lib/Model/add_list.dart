import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../cont/color.dart';
import 'package:agent_dart/agent.dart'; // Import the ICP agent package

class AddList extends StatefulWidget {
  const AddList({super.key});

  @override
  State<AddList> createState() => _AddListState();
}

class _AddListState extends State<AddList> {
  final list = TextEditingController();
  final price = TextEditingController();
  FocusNode _focusNode1 = FocusNode();
  FocusNode _focusNode2 = FocusNode();
  int indexx = 0;

  String formatPrice(String input) {
    input = input.replaceAll(',', '').replaceAll('₦', '');

    if (input.isEmpty) return '₦0';

    int value = int.tryParse(input) ?? 0;

    final formattedValue = value.toString().replaceAllMapped(
        RegExp(r'(\d)(?=(\d{3})+(?!\d))'), (Match match) => '${match[1]},');

    return '₦$formattedValue';
  }

  Future<void> addNote() async {
    final note = Note(
      DateTime.now().toString(), // Assuming you want to use timestamp as ID
      list.text,
      price.text,
      DateTime.now().toString(), // Add current time or implement as needed
      0, // Assuming image ID or placeholder; update as needed
      false, // Default is not done
    );

    try {
      // Interact with the ICP canister to save the note
      await ICPDatabase().saveNote(note); // Ensure you have an ICPDatabase class with a saveNote method
      Navigator.pop(context);
    } catch (e) {
      // Handle any errors here, such as showing a snackbar
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to add item: $e')));
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
        backgroundColor: backgroundColors,
        body: SafeArea(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              listWidgets(),
              SizedBox(height: 20),
              priceWidgets(),
              SizedBox(height: 20),
              button(),
            ],
          ),
        ),
      ),
    );
  }

  Widget button() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceAround,
      children: [
        ElevatedButton(
          style: ElevatedButton.styleFrom(
            primary: Colors.amber.shade400,
            minimumSize: Size(170, 48),
          ),
          onPressed: addNote, // Call the addNote method
          child: Text(
            'Add item',
            style: TextStyle(
              color: Colors.black,
              fontWeight: FontWeight.bold,
              fontSize: 16,
            ),
          ),
        ),
        ElevatedButton(
          style: ElevatedButton.styleFrom(
            primary: Colors.red,
            minimumSize: Size(170, 48),
          ),
          onPressed: () {
            Navigator.pop(context);
          },
          child: Text(
            'Cancel',
            style: TextStyle(
              color: Colors.black,
              fontWeight: FontWeight.bold,
              fontSize: 16,
            ),
          ),
        ),
      ],
    );
  }

  Widget listWidgets() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 15),
      child: Container(
        decoration: BoxDecoration(
          color: containerColors,
          borderRadius: BorderRadius.circular(15),
        ),
        child: TextField(
          controller: list,
          focusNode: _focusNode1,
          style: TextStyle(fontSize: 18, color: Color(0xffc5c5c5)),
          decoration: InputDecoration(
            contentPadding: EdgeInsets.symmetric(horizontal: 15, vertical: 15),
            hintText: 'Items',
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: BorderSide(
                color: Color(0xffc5c5c5),
                width: 2.0,
              ),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: BorderSide(
                width: 2.0,
              ),
            ),
          ),
        ),
      ),
    );
  }

  Padding priceWidgets() {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 15),
      child: Container(
        decoration: BoxDecoration(
          color: containerColors,
          borderRadius: BorderRadius.circular(15),
        ),
        child: TextField(
          controller: price,
          focusNode: _focusNode2,
          style: TextStyle(fontSize: 18, color: Color(0xffc5c5c5)),
          keyboardType: TextInputType.number,
          inputFormatters: [
            FilteringTextInputFormatter.digitsOnly,
          ],
          onChanged: (value) {
            if (value.isEmpty) return;

            final previousValue = value;
            final oldSelection = price.selection.start;

            setState(() {
              String formattedValue = formatPrice(value);

              price.text = formattedValue;

              int newSelection = formattedValue.length - (previousValue.length - oldSelection);
              newSelection = newSelection.clamp(0, formattedValue.length);

              price.selection = TextSelection.fromPosition(
                TextPosition(offset: newSelection),
              );
            });
          },
          decoration: InputDecoration(
            contentPadding: EdgeInsets.symmetric(horizontal: 15, vertical: 15),
            hintText: 'Price (₦0)',
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: BorderSide(
                color: Color(0xffc5c5c5),
                width: 2.0,
              ),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(10),
              borderSide: BorderSide(
                width: 2.0,
              ),
            ),
          ),
        ),
      ),
    );
  }
}



