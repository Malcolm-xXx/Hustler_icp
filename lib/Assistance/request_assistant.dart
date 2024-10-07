import 'dart:convert';

import 'package:http/http.dart' as http;


class RequestAssistant{
  static Future<dynamic> receiveRequest(String url) async{
    http.Response httpResponse = await http.get(Uri.parse(url));

    try {
      if(httpResponse.statusCode == 200)
      {
        String responseDate = httpResponse.body;
        var decodeReponseData = jsonDecode(responseDate);

        return decodeReponseData;
      }
      else{
        return "Error Occured No Response";
      }
    }
    catch(exp){
      return "Error Occured No Response";
    }

  }

}