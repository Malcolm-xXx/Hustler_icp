import 'package:agent_dart/agent.dart'; // Import the ICP agent package

class UserModel {
  String? phone;
  String? name;
  String? id;
  String? email;
  String? address;

  UserModel({
    this.email,
    this.id,
    this.name,
    this.phone,
    this.address,
  });

  // Constructor to create a UserModel from a map received from the ICP canister
  UserModel.fromMap(Map<String, dynamic> data, String userId) {
    phone = data["phone"];
    name = data["name"];
    email = data["email"];
    id = userId;
    address = data["address"];
  }
}

class Note {
  String id;
  String list;
  String price;
  String time;
  int image;
  bool isDon;

  Note(this.id, this.list, this.price, this.time, this.image, this.isDon);
}

// Example methods for ICP interaction (to be used in your repository or service class)
class ICPDatabase {
  final agent = Agent(); // Initialize your ICP agent

  Future<UserModel?> fetchUser(String userId) async {
    try {
      // Call your ICP canister's method to get user data
      final userData = await agent.call('getUser', [userId]);
      return UserModel.fromMap(userData, userId);
    } catch (e) {
      print('Error fetching user: $e');
      return null;
    }
  }

  Future<void> saveUser(UserModel user) async {
    try {
      // Call your ICP canister's method to save user data
      await agent.call('saveUser', [
        {
          'phone': user.phone,
          'name': user.name,
          'email': user.email,
          'address': user.address,
        }
      ]);
    } catch (e) {
      print('Error saving user: $e');
    }
  }

// Other methods for handling notes and additional functionality can be added here
}