import 'package:flutter/material.dart';

import '../Global/firestor.dart';
import '../Model/user_model.dart';
import '../Screen/edit_screen.dart';
import '../cont/color.dart';


class Task_Widget extends StatefulWidget {
  Note _note;
  Task_Widget(this._note, {super.key});

  @override
  State<Task_Widget> createState() => _Task_WidgetState();
}

class _Task_WidgetState extends State<Task_Widget> {
  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 15, vertical: 5),
      child: Container(
        width: double.infinity,
        height: 40,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          color: containerColors,
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 10),
          child: Expanded(
            child: Row(
              // imageee(),
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                Expanded(
                  child: Text(
                    widget._note.list,
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                ),

                SizedBox(width: 10),

                Text(
                  widget._note.price,
                  style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w400,
                      color: Colors.white
                  ),
                ),

                SizedBox(width: 10),

                GestureDetector(
                  onTap: () {
                    Navigator.of(context).push(MaterialPageRoute(
                      builder: (context) => Edit_Screen(widget._note),
                    ));
                  },
                  child: Icon(
                    Icons.edit,
                    color: Colors.grey, // Change icon color if necessary
                    size: 24, // Set the icon size
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }


  // Widget imageee() {
  //   return Container(
  //     height: 130,
  //     width: 100,
  //     decoration: BoxDecoration(
  //       color: Colors.white,
  //       image: DecorationImage(
  //         image: AssetImage('images/${widget._note.image}.png'),
  //         fit: BoxFit.cover,
  //       ),
  //     ),
  //   );
  // }
}

