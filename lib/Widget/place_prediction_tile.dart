import 'package:flutter/material.dart';
import '../Assistance/request_assistant.dart';
import '../Global/map_key.dart';
import '../Global/global.dart';
import '../Model/directions.dart';
import '../Model/predicted_places.dart';
import '../Widget/progress_dialog.dart';
import '../infoHandler/app_info.dart';
import 'package:provider/provider.dart';


class PlacePredictionTileDesign extends StatefulWidget {
  final PredictedPlaces? predictedPlaces;

  PlacePredictionTileDesign({this.predictedPlaces});

  @override
  State<PlacePredictionTileDesign> createState() => _PlacePredictionTileDesignState();
}

class _PlacePredictionTileDesignState extends State<PlacePredictionTileDesign> {

  getPlaceDirectionDetails(String? placeId,context) async {
    showDialog(
        context: context,
        builder: (BuildContext context) => ProgressDialog(
          message: "setting up Drop-off. Please wait.....",
        ),
    );
    String placeDirectionDetailsUrl = "https://maps.googleapis.com/maps/api/place/details/json?place_id=$placeId&key=$mapKey";

    var responseApi = await RequestAssistant.receiveRequest(placeDirectionDetailsUrl);

    Navigator.pop(context);

    if(responseApi == "Error Occured. Failed. No Response"){
      return;
    }

    if(responseApi["status"] == "ok"){
      Directions directions = Directions();
      directions.locationName = responseApi["result"]["name"];
      directions.locationId = placeId;
      directions.locationLatitude = responseApi["result"]["geometry"]["location"]["lat"];
      directions.locationLatitude = responseApi["result"]["geometry"]["location"]["lng"];

      Provider.of<AppInfo>(context, listen: false).updateDropOffLocationAddress(directions);

      setState(() {
        userDropOffAddress = directions.locationName!;
      });
      Navigator.pop(context, "obtainedDropOff");
    }
  }
  
  @override
  Widget build(BuildContext context) {

    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;
    return ElevatedButton(
        onPressed: (){
          getPlaceDirectionDetails(widget.predictedPlaces!.place_id, context);
        },
      style: ElevatedButton.styleFrom(
        primary: darkTheme ? Colors.black : Colors.white,
      ),
        child: Padding(
          padding: EdgeInsets.all(8.0),
          child: Row(
            children: [
              Icon(
                Icons.add_location,
                color: Colors.amber.shade400,
              ),
              SizedBox(width: 10,),

            Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      widget.predictedPlaces!.main_text!,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 16,
                        color: Colors.amber.shade400,
                      ),
                    ),

                    Text(
                      widget.predictedPlaces!.secondary_text!,
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontSize: 16,
                        color: Colors.amber.shade400,
                      ),
                    ),
                  ],
                ),
            ),
          ],
        ),
        ),
    );
  }
}
