import '../Model/direction_details_info.dart';
import '../Model/user_model.dart';
import 'package:agent_dart/agent.dart'; // Import the Dart agent library for ICP

// Initialize the ICP agent
final HttpAgent agent = HttpAgent(); // Replace FirebaseAuth instance with your ICP agent

// Global variables
UserModel? userModelCurrentInfo;
DirectionDetailsInfo? tripDirectionDetailsInfo;
String userDropOffAddress = "";

// Replace Firebase authentication logic
Future<void> authenticateUser(String username, String password) async {
  try {
    // Example authentication process (you would implement your own)
    // Call your ICP canister's authentication method here
    final canister = await agent.getCanister('bd3sg-teaaa-aaaaa-qaaba-cai&id=bkyz2-fmaaa-aaaaa-qaaaq-cai');
    currentUser = await canister.call('authenticateUser', [username, password]);

    // Load user info if authentication is successful
    await loadUserInfo(currentUser!.id);
  } catch (e) {
    print("Authentication error: $e");
  }
}

// Load user information from ICP canister
Future<void> loadUserInfo(String userId) async {
  try {
    final canister = await agent.getCanister('bd3sg-teaaa-aaaaa-qaaba-cai&id=bkyz2-fmaaa-aaaaa-qaaaq-cai');
    userModelCurrentInfo = await canister.call('getUserInfo', [userId]);
  } catch (e) {
    print("Error loading user info: $e");
  }
}
