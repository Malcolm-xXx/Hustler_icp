import 'dart:async';
import 'package:flutter_polyline_points/flutter_polyline_points.dart';
import 'package:geocoder2/geocoder2.dart';
import 'package:geolocator/geolocator.dart';
import 'package:google_maps_flutter/google_maps_flutter.dart';
import '../Global/global.dart';
import '../Global/map_key.dart';
import '../Screen/drawer_screen.dart';
import '../Screen/precise_pickup_location.dart';
import '../Screen/search_places_screen.dart';
import '../Widget/progress_dialog.dart';
import '../infoHandler/app_info.dart';
import 'package:location/location.dart' as loc;




import 'package:flutter/material.dart';
import '../Assistance/assistance_method.dart';
import 'package:provider/provider.dart';

import '../Model/directions.dart';



class GetHustlerScreen extends StatefulWidget {
  const GetHustlerScreen({super.key});

  @override
  State<GetHustlerScreen> createState() => _GetHustlerScreenState();
}

class _GetHustlerScreenState extends State<GetHustlerScreen> {
  LatLng? pickLocation;
  loc.Location location = loc.Location();
  String? _address;

  final Completer<GoogleMapController> _controllerGoogleMap = Completer();
  GoogleMapController? newGoogleMapController;

  static const CameraPosition _kGooglePlex = CameraPosition(
    target: LatLng(37.42796133580664, -122.085749655962),
    zoom: 14.4746,
  );

  final GlobalKey<ScaffoldState> _scaffoldState = GlobalKey<ScaffoldState>();

  double searchLocationContainerHeight = 200;
  double waitingResponsefromHustlerContainHeight = 0;
  double assignedHustlerInfoContainHeight = 0;

  Position? userCurrentPosition;
  var geoLocation = Geolocator();

  LocationPermission? _locationPermission;
  double bottomPaddingOfMap = 0;

  List<LatLng> pLingCoordinatedList =[];
  Set<Polyline> polylineSet ={};

  Set<Marker> markersSet ={};
  Set<Circle> circlesSet ={};

  String userName = "";
  String userEmail = "";

  bool openNavigationDrawer = true;
  bool activeNearbyHustlerKeysLoaded = false;

  BitmapDescriptor? activeNearbyIcon;

  locateUserPosition() async{
    Position cPosition = await Geolocator.getCurrentPosition(
        desiredAccuracy: LocationAccuracy.high);
    userCurrentPosition = cPosition;

    LatLng  latLngPosition =
    LatLng(userCurrentPosition!.latitude, userCurrentPosition!.longitude);
    CameraPosition cameraPosition =
    CameraPosition(target: latLngPosition, zoom: 15);

    newGoogleMapController!.animateCamera(
        CameraUpdate.newCameraPosition(cameraPosition)
    );

    String humanReadableAddress =
    await AssistanceMethods.searchAddressForGeographicCoordinates( userCurrentPosition!, context);
    print("This is our address = " + humanReadableAddress);

    userName = userModelCurrentInfo!.name!;
    userEmail = userModelCurrentInfo!.email!;

    // initializeGeoFireListener();
    // AssistanceMethods.readTripsKeysForOnlineUser();
  }

  Future<void>drawPolyLineFromOriginToDestination(bool darkTheme) async{
    var originPosition = Provider.of<AppInfo>(context, listen: false).userPickUpLocation;
    var destinationPosition = Provider.of<AppInfo>(context, listen: false).userDropOffLocation;

    var originLatLng =  LatLng(originPosition!.locationLatitude!, originPosition.locationLongitude!);
    var destinationLatLng =  LatLng(destinationPosition!.locationLatitude!, destinationPosition.locationLongitude!);


    showDialog(
      context: context,
      builder: (BuildContext context) => ProgressDialog(message: "Please wait...",),
    );

    var directionDetailsInfo = await AssistanceMethods.obtainOriginToDestinationDirectionDetails(originLatLng, destinationLatLng);
    setState(() {
      tripDirectionDetailsInfo = directionDetailsInfo;
    });


    Navigator.pop(context);

    PolylinePoints pPoints = PolylinePoints();
    List<PointLatLng> decodePolyLinePointsResultList = pPoints.decodePolyline(directionDetailsInfo.e_points!);

    pLingCoordinatedList.clear();

    if(decodePolyLinePointsResultList.isNotEmpty) {
      decodePolyLinePointsResultList.forEach((PointLatLng pointLatLng) {
        pLingCoordinatedList.add(LatLng(pointLatLng.latitude, pointLatLng.longitude));
      });
    }

    polylineSet.clear();

    setState(() {
      Polyline polyline = Polyline(
        color: Colors.grey,
        polylineId: PolylineId("PolylineID"),
        jointType: JointType.round,
        points: pLingCoordinatedList,
        startCap: Cap.roundCap,
        endCap: Cap.roundCap,
        geodesic: true,
        width: 5,
      );


      polylineSet.add(polyline);
    });
    LatLngBounds boundsLatLng;
    if(originLatLng.latitude > destinationLatLng.latitude && originLatLng.longitude > destinationLatLng.longitude){
      boundsLatLng = LatLngBounds( southwest: destinationLatLng, northeast: originLatLng);
    }
    else if (originLatLng.longitude > destinationLatLng.longitude){
      boundsLatLng = LatLngBounds(
        southwest: LatLng(originLatLng.latitude, destinationLatLng.longitude),
        northeast: LatLng(destinationLatLng.latitude, originLatLng.longitude),
      );
    }
    else if (originLatLng.latitude > destinationLatLng.latitude){
      boundsLatLng = LatLngBounds(
        southwest: LatLng(destinationLatLng.latitude, originLatLng.longitude),
        northeast: LatLng(originLatLng.latitude, destinationLatLng.longitude),
      );
    }
    else {
      boundsLatLng = LatLngBounds(
        southwest: originLatLng,
        northeast: destinationLatLng,
      );
    }

    newGoogleMapController!.animateCamera(CameraUpdate.newLatLngBounds(boundsLatLng, 65));

    Marker originMarker = Marker(
        markerId: const MarkerId("originID"),
        infoWindow: InfoWindow(title: originPosition.locationName, snippet: "Origin"),
        position: originLatLng,
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueGreen)
    );

    Marker destinationMarker = Marker(
        markerId: const MarkerId("destinationID"),
        infoWindow: InfoWindow(title: destinationPosition.locationName, snippet: "Destination"),
        position: destinationLatLng,
        icon: BitmapDescriptor.defaultMarkerWithHue(BitmapDescriptor.hueRed)
    );

    setState(() {
      markersSet.add(originMarker);
      markersSet.add(destinationMarker);
    });

    Circle originCircle = Circle(
      circleId: CircleId("originID"),
      fillColor: Colors.green,
      radius: 12,
      strokeWidth: 3,
      strokeColor: Colors.white,
      center: originLatLng,
    );

    Circle destinationCircle = Circle(
      circleId: CircleId("destinationID"),
      fillColor: Colors.red,
      radius: 12,
      strokeWidth: 3,
      strokeColor: Colors.white,
      center: destinationLatLng,
    );

    setState(() {
      circlesSet.add(originCircle);
      circlesSet.add(destinationCircle);
    });
  }


  // getAddressFromLatLng() async{
  //    try{
  //      GeoData data = await Geocoder2.getDataFromCoordinates(
  //          latitude: pickLocation!.latitude,
  //          longitude: pickLocation!.longitude,
  //          googleMapApiKey: mapKey
  //      );
  //      setState(() {
  //        Directions userPickUpAddress = Directions();
  //        userPickUpAddress.locationLatitude = pickLocation!.latitude;
  //        userPickUpAddress.locationLongitude = pickLocation!.longitude;
  //        userPickUpAddress.locationName = data.address;
  //
  //        Provider.of<AppInfo>(context, listen: false).updatePickUpLocationAddress(userPickUpAddress);
  //
  //
  //        //_address = data.address;
  //      });
  //    }
  //    catch(e){
  //      print(e);
  //    }
  // }

  checkIfLocationPermissionAllowed() async{
    _locationPermission = await Geolocator.requestPermission();
    if(_locationPermission == LocationPermission.denied){
      _locationPermission = await Geolocator.requestPermission();
    }
  }

  @override
  void initState() {
    //TODO:implement initState
    super.initState();

    checkIfLocationPermissionAllowed();
  }



  @override
  Widget build(BuildContext context) {
    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;
    return GestureDetector(
      onTap: () {
        FocusScope.of(context).unfocus();
      },
      child:  Scaffold(
        key: _scaffoldState,
        drawer: DrawerScreen(),
        body: Stack(
          children: [
            GoogleMap(
              padding: EdgeInsets.only(top: 30, bottom: bottomPaddingOfMap),
              mapType: MapType.normal,
              myLocationEnabled: true,
              zoomGesturesEnabled: true,
              zoomControlsEnabled: true,
              initialCameraPosition: _kGooglePlex,
              polylines: polylineSet,
              markers: markersSet,
              circles: circlesSet,
              onMapCreated: (GoogleMapController controller){
                _controllerGoogleMap.complete(controller);
                newGoogleMapController = controller;


                setState(() {
                  bottomPaddingOfMap = 200;
                });
                locateUserPosition();
              },
              // onCameraMove: (CameraPosition? position){
              //   if(pickLocation != position!.target){
              //     setState(() {
              //       pickLocation = position.target;
              //     });
              //   }
              // },
              // onCameraIdle: (){
              //   getAddressFromLatLng();
              // },
            ),

            // Align(
            //   alignment: Alignment.center,
            //   child: Padding (
            //     padding: EdgeInsets.only(bottom: bottomPaddingOfMap),
            //     child: Image.asset("asset/images/img.png",height: 45,width: 45,),
            //   ),
            // ),

            // menu
            Positioned(
              top: 50,
              left: 20,
              child: Container(
                child: GestureDetector(
                  onTap: (){
                    _scaffoldState.currentState!.openDrawer();
                  },
                  child: CircleAvatar(
                    backgroundColor: Colors.amber.shade400,
                    child: Icon(
                      Icons.menu,
                      color: darkTheme? Colors.black : Colors.white,
                    ),
                  ),
                ),
              ),

            ),


            Positioned(
              bottom: 0,
              left: 0,
              right: 0,
              child: Container(
                height: 200,
                decoration: BoxDecoration(
                  color: darkTheme ? Color(0xFF1B1A28) : Colors.white,
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(60),
                    topRight: Radius.circular(60),
                  ),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(30),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      ElevatedButton(
                        onPressed: () async {
                          var responseFromSearchScreen = await Navigator.push(
                            context,
                            MaterialPageRoute(builder: (context) => SearchPlaceScreen(),
                            ),
                          );
                          // if (responseFromSearchScreen == "obtainedDropoff") {
                          //   setState(() {
                          //     openNavigationDrawer = false;
                          //   });
                          // }
                          // //await drawPolyLineFromOriginToDestination(darkTheme);
                        },
                        style: ElevatedButton.styleFrom(
                          primary: Colors.amber.shade400,
                          onPrimary: darkTheme ? Colors.black : Colors.white,
                          elevation: 10,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(32),
                          ),
                          minimumSize: const Size(double.infinity, 50),
                        ),
                        child: const Text(
                          "Get Hustler",
                          style: TextStyle(
                            fontSize: 20,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),


          ],
        ),

      ),

    );
  }
}