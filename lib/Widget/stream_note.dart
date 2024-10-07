import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter/material.dart';
import '../Model/user_model.dart';
import '../Widget/task_widgets.dart';

import '../Global/firestor.dart';


class Stream_note extends StatelessWidget {
  final bool done;
  final ValueNotifier<double> totalPriceNotifier;
  final Function(List<Note>) onNotesUpdated;

  Stream_note(this.done, {required this.totalPriceNotifier, required this.onNotesUpdated, super.key});

  @override
  Widget build(BuildContext context) {
    // Initialize Firestore_Datasource instance only once
    final firestoreDatasource = Firestore_Datasource();

    return StreamBuilder<QuerySnapshot>(
      stream: firestoreDatasource.stream(done),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return Center(child: CircularProgressIndicator());
        }

        if (snapshot.hasError) {
          return Center(child: Text('Error loading item'));
        }

        final List noteslist = firestoreDatasource.getNotes(snapshot);

        // Calculate total price by summing the price of each note
        double totalPrice = 0.0;
        for (var note in noteslist) {
          totalPrice += double.tryParse(note.price.toString()) ?? 0.0; // Assuming each 'note' has a 'price' field
        }

        // Update the total price in the parent
        totalPriceNotifier.value = totalPrice;

        // WidgetsBinding.instance.addPostFrameCallback((_) {
        //   onNotesUpdated(noteslist); // Ensure this is called after the build phase
        // });

        return ListView.builder(
          shrinkWrap: true,
          physics: NeverScrollableScrollPhysics(), // Disable scrolling to avoid conflicts
          itemCount: noteslist.length,
          itemBuilder: (context, index) {
            final note = noteslist[index];
            return Dismissible(
              key: UniqueKey(),
              onDismissed: (direction) {
                firestoreDatasource.delet_note(note.id);
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text("item deleted")),
                );
              },
              child: Task_Widget(note),
            );
          },
        );
      },
    );
  }
}
