import 'package:flutter/material.dart';
import 'package:geolocator/geolocator.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:provider/provider.dart';
import '../Model/direction_details_info.dart';
import '../Model/user_model.dart';
import '../Global/global.dart';
import '../infoHandler/app_info.dart';
import '../Assistance/request_assistant.dart';


// Assume necessary ICP imports are included
// e.g., for ICP agent initialization and canister interaction

class AssistanceMethods {
  static Future<void> readCurrentOnlineUserInfo() async {
    // Assuming a method to get the current user's principal from ICP
    currentUser = await getCurrentUserPrincipal(); // Replace with your ICP logic

    if (currentUser != null) {
      // Call to the canister to retrieve user data
      final userSnapshot = await actor.call('getUserInfo', [currentUser]);

      if (userSnapshot != null) {
        userModelCurrentInfo = UserModel.fromSnapshot(userSnapshot);
      }
    }
  }

  static Future<String> searchAddressForGeographicCoordinates(Position position, BuildContext context) async {
    // Replace with a mapping service API if needed
    String apiUrl = "https://maps.googleapis.com/maps/api/geocode/json?latlng=${position.latitude},${position.longitude}&key=$mapKey";
    String humanReadableAddress = "";

    var requestResponse = await RequestAssistant.receiveRequest(apiUrl);

    if (requestResponse != "Error Occurred No Response") {
      humanReadableAddress = requestResponse["results"][0]["formatted_address"];

      Directions userPickUpAddress = Directions();
      userPickUpAddress.locationLatitude = position.latitude;
      userPickUpAddress.locationLongitude = position.longitude;
      userPickUpAddress.locationName = humanReadableAddress;

      Provider.of<AppInfo>(context, listen: false).updatePickUpLocationAddress(userPickUpAddress);
    }

    return humanReadableAddress;
  }

  static Future<DirectionDetailsInfo> obtainOriginToDestinationDirectionDetails(LatLng originPosition, LatLng destinationPosition) async {
    String urlOriginToDestinationDirectionDetails = "https://maps.googleapis.com/maps/api/directions/json?origin=${originPosition.latitude},${originPosition.longitude}&destination=${destinationPosition.latitude},${destinationPosition.longitude}&key=$mapKey";

    var responseDirectionApi = await RequestAssistant.receiveRequest(urlOriginToDestinationDirectionDetails);

    DirectionDetailsInfo directionDetailsInfo = DirectionDetailsInfo();
    directionDetailsInfo.e_points = responseDirectionApi["routes"][0]["overview_polyline"]["points"];

    directionDetailsInfo.duration_value = responseDirectionApi["routes"][0]["legs"][0]["duration"]["value"];
    directionDetailsInfo.duration_text = responseDirectionApi["routes"][0]["legs"][0]["duration"]["text"];

    directionDetailsInfo.distance_value = responseDirectionApi["routes"][0]["legs"][0]["distance"]["value"];
    directionDetailsInfo.distance_text = responseDirectionApi["routes"][0]["legs"][0]["distance"]["text"];

    return directionDetailsInfo;
  }
}
