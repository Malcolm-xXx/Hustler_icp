import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../Global/firestor.dart';
import '../Model/user_model.dart';
import '../cont/color.dart';


class Edit_Screen extends StatefulWidget {
  Note _note;
  Edit_Screen(this._note, {super.key});

  @override
  State<Edit_Screen> createState() => _Edit_ScreenState();
}

class _Edit_ScreenState extends State<Edit_Screen> {
  TextEditingController? list;
  TextEditingController? price;

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

  @override
  void initState() {
    // TODO: implement initState
    super.initState();
    list = TextEditingController(text: widget._note.list);
    price = TextEditingController(text: widget._note.price);
  }

  Widget build(BuildContext context) {
    return GestureDetector(
      onTap:() {
        FocusScope.of(context).unfocus();
      },
      child: Scaffold(
        backgroundColor: backgroundColors,
        body: SafeArea(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              list_widgets(),
              SizedBox(height: 20),
              price_widgets(),
              SizedBox(height: 20),
              //images(),
              SizedBox(height: 20),
              button()
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
          onPressed: () {
            Firestore_Datasource().Update_Note(
                widget._note.id, indexx, list!.text, price!.text);
            Navigator.pop(context);
          },
          child: Text('Add item',
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
          child: Text('Cancel',
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

  // Container imagess() {
  //   return Container(
  //     height: 180,
  //     child: ListView.builder(
  //       itemCount: 4,
  //       scrollDirection: Axis.horizontal,
  //       itemBuilder: (context, index) {
  //         return GestureDetector(
  //           onTap: () {
  //             setState(() {
  //               indexx = index;
  //             });
  //           },
  //           child: Padding(
  //             padding: EdgeInsets.only(left: index == 0 ? 7 : 0),
  //             child: Container(
  //               decoration: BoxDecoration(
  //                 borderRadius: BorderRadius.circular(10),
  //                 border: Border.all(
  //                   width: 2,
  //                   color: indexx == index ? custom_green : Colors.grey,
  //                 ),
  //               ),
  //               width: 140,
  //               margin: EdgeInsets.all(8),
  //               child: Column(
  //                 children: [
  //                   Image.asset('images/${index}.png'),
  //                 ],
  //               ),
  //             ),
  //           ),
  //         );
  //       },
  //     ),
  //   );
  // }

  Widget list_widgets() {
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
          style: TextStyle(fontSize: 18, color: Colors.black),
          decoration: InputDecoration(
              contentPadding:
              EdgeInsets.symmetric(horizontal: 15, vertical: 15),
              hintText: 'items',
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
                  // color: custom_green,
                  width: 2.0,
                ),
              )),
        ),
      ),
    );
  }

  Padding price_widgets() {
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
          style: TextStyle(fontSize: 18, color: Colors.black),
          keyboardType: TextInputType.number, // Only allow numeric inputs
          inputFormatters: [
            FilteringTextInputFormatter.digitsOnly, // Allow only digits
          ],
          onChanged: (value) {
            if (value.isEmpty) return;

            // Capture cursor position before formatting
            final previousValue = value;
            final oldSelection = price!.selection.start;

            setState(() {
              // Format the value
              String formattedValue = formatPrice(value);

              // Update text and reset the cursor position
              price!.text = formattedValue;

              // Calculate the new cursor position after formatting
              int newSelection = formattedValue.length -
                  (previousValue.length - oldSelection);

              // Ensure the cursor is not outside the bounds of the text
              newSelection = newSelection.clamp(0, formattedValue.length);

              price!.selection = TextSelection.fromPosition(
                TextPosition(offset: newSelection),
              );
            });
          },
          decoration: InputDecoration(
            contentPadding: EdgeInsets.symmetric(horizontal: 15, vertical: 15),
            hintText: 'price (₦0)',
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
