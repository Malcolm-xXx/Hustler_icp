import 'package:flutter/material.dart';
import '../Screen/my%20_list_screen.dart';
import 'package:provider/provider.dart';
import '../Assistance/request_assistant.dart';
import '../Global/map_key.dart';
import '../Model/predicted_places.dart';
import '../Widget/place_prediction_tile.dart';
import '../infoHandler/app_info.dart';


class SearchPlaceScreen extends StatefulWidget {
  const SearchPlaceScreen({super.key});

  @override
  State<SearchPlaceScreen> createState() => _SearchPlaceScreenState();
}

class _SearchPlaceScreenState extends State<SearchPlaceScreen> {

  List<PredictedPlaces> placesPredictedList = [];
  TextEditingController locationController = TextEditingController();
  TextEditingController marketController = TextEditingController();

   findPlaceAutoCompleteSearch(String inputText) async {
     if(inputText.length > 1){
       String urlAutoCompleteSearch = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=$inputText&key=$mapKey&components=country:NG";

       var responseAutoCompleteSearch =  await RequestAssistant.receiveRequest(urlAutoCompleteSearch);


       if(responseAutoCompleteSearch == "Error Occurred. Failed. No Response"){
         return;
       }

       if(responseAutoCompleteSearch["status"] == "ok"){
          var placePredictions = responseAutoCompleteSearch["predictions"];

           var placePredictionsList = (placePredictions as List).map((jsonData) => PredictedPlaces.fromJson(jsonData)).toList();

          setState(() {
          placesPredictedList = placePredictionsList;
          });
       }
     }
   }

  // void checkIfBothFieldsFilled() {
  //   if (locationController.text.isNotEmpty && marketController.text.isNotEmpty) {
  //     //Navigate to the next page if both fields are filled
  //     Navigator.push(
  //       context,
  //       MaterialPageRoute(builder: (context) => MyListScreen() ), // Replace with your actual page
  //     );
  //   }
  // }

  void checkIfBothFieldsFilled() {
    // Ensure both fields have at least 10 characters before proceeding
    if (locationController.text.length >= 10 && marketController.text.length >= 10) {
      // Navigate to the next page
      Navigator.push(
        context,
        MaterialPageRoute(builder: (context) => MyListScreen() ), // Replace with your actual page
      );
    }
  }

  @override
  void initState() {
    super.initState();

    // Initialize the TextField with the current location if available
    if (Provider.of<AppInfo>(context, listen: false).userPickUpLocation != null) {
      locationController.text = (Provider.of<AppInfo>(context, listen: false).userPickUpLocation!.locationName!).substring(0, 24) +"...";
    }
    else{
      locationController.text = "Not Getting Address";
    }
  }

  // void updateLocation(String value) {
  //   setState(() {
  //     locationController.text = value;
  //   });
  //
  //   // Perform the search prediction based on user input
  //   findPlaceAutoCompleteSearch(value);
  //   checkIfBothFieldsFilled();
  // }

  void updateLocation(String value) {
    if (value.length > 1) {
      findPlaceAutoCompleteSearch(value);
    }
    checkIfBothFieldsFilled(); // Call after setting the text
  }

  // void updateMarket(String value) {
  //   setState(() {
  //     marketController.text = value;
  //   });
  //   findPlaceAutoCompleteSearch(value);
  //   checkIfBothFieldsFilled();
  // }

  void updateMarket(String value) {
    if (value.length > 1) {
      findPlaceAutoCompleteSearch(value);
    }
    checkIfBothFieldsFilled(); // Call after setting the text
  }


  @override
  Widget build(BuildContext context) {

    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;

    return GestureDetector(
      onTap:() {
        FocusScope.of(context).unfocus();
      },
      child: Scaffold(
        backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),

        appBar: AppBar(
          backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
           toolbarHeight: 40,
            leading: GestureDetector(
              onTap: (){
                Navigator.pop(context);
              },
              child: Icon(Icons.arrow_back, color: Color(0xFF767E9E) ),
            ),
        ),

        body: Column(
          children: [
            Container(
              decoration: BoxDecoration(
               color: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
               boxShadow: [
                 BoxShadow(
                   color: Colors.white54,
                   blurRadius: 4,
                   spreadRadius: 0.2,
                   offset: Offset(0.3, 0.3,
                   ),
                 ),
               ],
              ),
              child: Padding(
                padding: EdgeInsets.all(10.0),
                child: Column(
                  children: [
                    Row(
                      children: [
                        Icon(
                          Icons.adjust_sharp,
                          color: Color(0xFF34D186),
                        ),
                        
                        SizedBox(height: 10.0,),
                        
                        Expanded(
                          child: Padding(
                            padding: EdgeInsets.all(8),
                            child: Container(
                              decoration: BoxDecoration(
                                color: Color(0xff464c64),
                                borderRadius: BorderRadius.circular(10), // Circular edges
                              ),
                              child: TextField(
                                controller: locationController,
                                onChanged: (value) {
                                  updateLocation(value); // Update the text and trigger predictions
                                },
                                decoration: InputDecoration(
                                  hintText: "Search location here...",
                                  border: InputBorder.none,
                                  contentPadding: EdgeInsets.only(
                                    left: 11,
                                    top: 8,
                                    bottom: 8,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),

                    SizedBox(height: 2,),


                    Row(
                      children: [
                        Icon(
                          Icons.location_on_outlined,
                          color: Color(0xFF7C6DDD),
                        ),

                        SizedBox(height: 18.0,),

                        Expanded(
                          child: Padding(
                            padding: EdgeInsets.all(8),
                            child: Container(
                              decoration: BoxDecoration(
                                color: Color(0xff464c64),
                                borderRadius: BorderRadius.circular(10), // Circular edges
                              ),
                              child: TextField(
                                controller: marketController,
                                onChanged: (value) {
                                  updateMarket(value);
                                },
                                decoration: InputDecoration(
                                  hintText: "Recommended market...",
                                  border: InputBorder.none,
                                  contentPadding: EdgeInsets.only(
                                    left: 11,
                                    top: 8,
                                    bottom: 8,
                                  ),
                                ),
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),

            // Display prediction
            (placesPredictedList.length > 0)
            ?Expanded(
                child: ListView.separated(
                  itemCount: placesPredictedList.length,
                  physics: ClampingScrollPhysics(),
                  itemBuilder: (context, index){
                      return PlacePredictionTileDesign(
                        predictedPlaces: placesPredictedList[index],
                      );
                  },
                    separatorBuilder:(BuildContext context, int index) {
                    return Divider(
                      height: 0,
                      color: Colors.grey,
                      thickness: 0,
                      );
                    },
                ),
            ):Container(),
          ],
        ),
      ),
    );
  }
}
