import 'package:agent_dart/agent_dart.dart';
import 'package:flutter/material.dart';
import 'package:uuid/uuid.dart';
import '../Model/user_model.dart';

// Define the ICP agent and actor for interacting with the canister
final HttpAgent icpAgent = HttpAgent(
  options: HttpAgentOptions(
    host: 'http://127.0.0.1:4943', // Replace with your Internet Computer host
  ),
);



final Principal canisterId = Principal.fromText('bd3sg-teaaa-aaaaa-qaaba-cai&id=bkyz2-fmaaa-aaaaa-qaaaq-cai'); // Replace with your canister id

// Assuming the canister's IDL is already generated
final actor = Actor.createActor(
  idlFactory, // Define your IDL factory
  ActorConfig(
    canisterId: canisterId,
    agent: icpAgent,
  ),
);

class ICPDatasource {
  Principal? currentUser; // Current user principal

  // Function to create a user
  Future<bool> createUser(String email) async {
    try {
      if (currentUser != null) {
        await actor.call('createUser', [currentUser, email]);
        return true;
      }
      return false;
    } catch (e) {
      print(e);
      return false;
    }
  }

  // Function to add a note
  Future<bool> addNote(String list, String price, int image) async {
    try {
      var uuid = Uuid().v4();
      DateTime data = DateTime.now();
      if (currentUser != null) {
        await actor.call('addNote', [
          currentUser,
          uuid,
          list,
          price,
          false,
          image,
          '${data.hour}:${data.minute}'
        ]);
        return true;
      }
      return false;
    } catch (e) {
      print(e);
      return false;
    }
  }

  // Function to retrieve notes (replace with your canister's logic)
  Future<List<Note>> getNotes() async {
    try {
      if (currentUser != null) {
        final notes = await actor.call('getNotes', [currentUser]);
        return (notes as List).map((data) {
          return Note(
            data['id'],
            data['list'],
            data['price'],
            data['time'],
            data['image'],
            data['isDon'],
          );
        }).toList();
      }
      return [];
    } catch (e) {
      print(e);
      return [];
    }
  }

  // Function to stream notes
  Stream<List<Note>> streamNotes(bool isDone) async* {
    try {
      if (currentUser != null) {
        final notes = await actor.call('streamNotes', [currentUser, isDone]);
        yield (notes as List).map((data) {
          return Note(
            data['id'],
            data['list'],
            data['price'],
            data['time'],
            data['image'],
            data['isDon'],
          );
        }).toList();
      } else {
        yield [];
      }
    } catch (e) {
      print(e);
      yield [];
    }
  }

  // Function to update a note
  Future<bool> updateNote(String uuid, int image, String list, String price) async {
    try {
      DateTime data = DateTime.now();
      if (currentUser != null) {
        await actor.call('updateNote', [
          currentUser,
          uuid,
          '${data.hour}:${data.minute}',
          price,
          list,
          image,
        ]);
        return true;
      }
      return false;
    } catch (e) {
      print(e);
      return false;
    }
  }

  // Function to delete a note
  Future<bool> deleteNote(String uuid) async {
    try {
      if (currentUser != null) {
        await actor.call('deleteNote', [currentUser, uuid]);
        return true;
      }
      return false;
    } catch (e) {
      print(e);
      return false;
    }
  }

  // Function to send notes to vendor (implement canister logic)
  Future<void> sendNotesToVendor(List<Note> notes) async {
    for (var note in notes) {
      try {
        await actor.call('sendNoteToVendor', [
          note.list,
          note.price,
          DateTime.now().millisecondsSinceEpoch
        ]);
      } catch (e) {
        print("Error sending note to vendor: $e");
      }
    }
  }
}

