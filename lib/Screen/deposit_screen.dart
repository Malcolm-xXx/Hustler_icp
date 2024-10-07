import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:flutter/services.dart'; // For copy functionality

class DepositScreen extends StatefulWidget {
  final String assetName; // e.g., BTC, GTB
  final String walletAddress; // The wallet address or bank account number
  final String network; // Initial network (for crypto assets)
  final String memoId; // Memo ID for assets that require it (optional)

  const DepositScreen({
    Key? key,
    required this.assetName,
    required this.walletAddress,
    required this.network,
    this.memoId = '', // Optional, empty by default
  }) : super(key: key);

  @override
  State<DepositScreen> createState() => _DepositScreenState();
}

class _DepositScreenState extends State<DepositScreen> {
  // Network dropdown options for crypto
  final List<String> _networks = ['Bitcoin', 'Ethereum', 'Binance Smart Chain', 'Polygon'];
  String _selectedNetwork = '';

  @override
  void initState() {
    super.initState();
    _selectedNetwork = widget.network; // Set initial network
  }

  // Method to copy wallet address to clipboard
  void _copyToClipboard(String text) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Copied to clipboard')),
    );
  }

  @override
  Widget build(BuildContext context) {
    bool isCrypto = widget.assetName != 'GTB'; // Assume that bank is GTB, others are crypto

    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(widget.assetName), // Dynamic title based on assetName
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // QR Code / Barcode Section
            // Center(
            //   child: QrImage(
            //     data: widget.walletAddress, // Data encoded in the QR code
            //     size: 200, // QR code size
            //   ),
            // ),
            SizedBox(height: 20),

            // Wallet Address / Bank Account Section
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  isCrypto ? 'Wallet Address' : 'Bank Account',
                  style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                ),
                IconButton(
                  icon: Icon(Icons.copy),
                  onPressed: () => _copyToClipboard(widget.walletAddress),
                ),
              ],
            ),
            SizedBox(height: 4),
            Text(
              widget.walletAddress,
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 20),

            // Network Section (Only for crypto)
            // if (isCrypto)
            //   Column(
            //     crossAxisAlignment: CrossAxisAlignment.start,
            //     children: [
            //       Text(
            //         'Network',
            //         style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
            //       ),
            //       SizedBox(height: 8),
            //       Container(
            //         padding: EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            //         decoration: BoxDecoration(
            //           borderRadius: BorderRadius.circular(8),
            //           color: Colors.grey[200],
            //         ),
            //         child: DropdownButton<String>(
            //           value: _selectedNetwork,
            //           isExpanded: true,
            //           underline: SizedBox(),
            //           items: _networks.map((String network) {
            //             return DropdownMenuItem<String>(
            //               value: network,
            //               child: Text(network),
            //             );
            //           }).toList(),
            //           onChanged: (String? newValue) {
            //             setState(() {
            //               _selectedNetwork = newValue!;
            //             });
            //           },
            //         ),
            //       ),
            //       SizedBox(height: 20),
            //     ],
            //   ),

            // Memo ID or Tag Section (Only for crypto assets that require it)
            if (isCrypto && widget.memoId.isNotEmpty)
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Memo ID / Tag',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                  SizedBox(height: 4),
                  Text(
                    widget.memoId,
                    style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                  ),
                  SizedBox(height: 20),
                ],
              ),
          ],
        ),
      ),
    );
  }
}

