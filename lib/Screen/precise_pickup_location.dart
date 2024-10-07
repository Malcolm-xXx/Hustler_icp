import 'dart:async';

import 'package:flutter/material.dart';
import 'package:geocoder2/geocoder2.dart';
import 'package:geolocator/geolocator.dart';
import 'package:location/location.dart' as loc;
import 'package:google_maps_flutter/google_maps_flutter.dart';
import 'package:provider/provider.dart';

import '../Assistance/assistance_method.dart';
import '../Global/map_key.dart';
import '../Model/directions.dart';
import '../infoHandler/app_info.dart';

 
 class PrecisePickUpScreen extends StatefulWidget {
   const PrecisePickUpScreen({super.key});
 
   @override
   State<PrecisePickUpScreen> createState() => _PrecisePickUpScreenState();
 }
 
 class _PrecisePickUpScreenState extends State<PrecisePickUpScreen> {

  LatLng? pickLocation;
   loc.Location location = loc.Location();
   String? _address;

   final Completer<GoogleMapController> _controllerGoogleMap = Completer();
   GoogleMapController? newGoogleMapController;

  Position? userCurrentPosition;
  double bottomPaddingOfMap = 0;

   static const CameraPosition _kGooglePlex = CameraPosition(
     target: LatLng(37.42796133580664, -122.085749655962),
     zoom: 14.4746,
   );

   GlobalKey<ScaffoldState> _scaffoldState = GlobalKey<ScaffoldState>();

  locateUserPosition() async{
    Position cPosition = await Geolocator.getCurrentPosition(
        desiredAccuracy: LocationAccuracy.high);
    userCurrentPosition = cPosition;

    LatLng  latLngPosition = LatLng(userCurrentPosition!.latitude, userCurrentPosition!.longitude);
    CameraPosition cameraPosition = CameraPosition(target: latLngPosition, zoom: 15);

    newGoogleMapController!.animateCamera(CameraUpdate.newCameraPosition(cameraPosition));

    String humanReadableAddress = await AssistanceMethods.searchAddressForGeographicCoordinates( userCurrentPosition!, context);
  }

  getAddressFromLatLng() async{
     try{
       GeoData data = await Geocoder2.getDataFromCoordinates(
           latitude: pickLocation!.latitude,
           longitude: pickLocation!.longitude,
           googleMapApiKey: mapKey
       );
       setState(() {
         Directions userPickUpAddress = Directions();
         userPickUpAddress.locationLatitude = pickLocation!.latitude;
         userPickUpAddress.locationLongitude = pickLocation!.longitude;
         userPickUpAddress.locationName = data.address;

         Provider.of<AppInfo>(context, listen: false).updatePickUpLocationAddress(userPickUpAddress);


         //_address = data.address;
       });
     }
     catch(e){
       print(e);
     }
  }

   @override
   Widget build(BuildContext context) {
     return Scaffold(
       body: Stack(
         children: [
           GoogleMap(
             padding: EdgeInsets.only(top: 100, bottom: bottomPaddingOfMap),
             mapType: MapType.normal,
             myLocationEnabled: true,
             zoomGesturesEnabled: true,
             zoomControlsEnabled: true,
             initialCameraPosition: _kGooglePlex,
             onMapCreated: (GoogleMapController controller){
               _controllerGoogleMap.complete(controller);
               newGoogleMapController = controller;


               setState(() {
                 bottomPaddingOfMap = 50;
               });

               locateUserPosition();
             },
             onCameraMove: (CameraPosition? position){
               if(pickLocation != position!.target){
                 setState(() {
                   pickLocation = position.target;
                 });
               }
             },
             onCameraIdle: (){
               getAddressFromLatLng();
             },
           ),

           Align(
             alignment: Alignment.center,
             child: Padding (
               padding: EdgeInsets.only( top: 60, bottom: bottomPaddingOfMap),
               child: Image.asset("asset/images/img.png",height: 45,width: 45,),
             ),
           ),
         ],
       ),
     );
   }
 }
 