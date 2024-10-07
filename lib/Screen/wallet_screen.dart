
import 'package:flutter/material.dart';
import 'package:font_awesome_flutter/font_awesome_flutter.dart';
import 'package:hustleruser/cont/color.dart'; // Import your custom colors
import '../Screen/deposit_screen.dart';

class WalletScreen extends StatefulWidget {
  const WalletScreen({Key? key}) : super(key: key);

  @override
  State<WalletScreen> createState() => _WalletScreenState();
}

class _WalletScreenState extends State<WalletScreen> {
  bool isBalanceHidden = false;
  double totalBalance = 5000.00; // Example balance, includes bank and crypto amounts

  // Method to toggle balance visibility
  void toggleBalanceVisibility() {
    setState(() {
      isBalanceHidden = !isBalanceHidden;
    });
  }

  // Helper method to navigate to the Deposit Screen
  void navigateToDepositScreen({
    required String assetName,
    required String walletAddress,
    required String network,
    String memoId = '',
  }) {
    // Navigator.push(
    //   context,
    //   MaterialPageRoute(
    //     builder: (context) => DepositScreen(
    //       assetName: assetName,
    //       walletAddress: walletAddress,
    //       network: network,
    //       memoId: memoId,
    //     ),
    //   ),
    // );
  }

  @override
  Widget build(BuildContext context) {
    bool darkTheme = MediaQuery.of(context).platformBrightness == Brightness.dark;

    return Scaffold(
      backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
      appBar: AppBar(
        backgroundColor: darkTheme ? Color(0xFFF1B1A28) : Color(0xFF464C64),
        leading: IconButton(
          icon: Icon(Icons.arrow_back),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text('Wallet'),
        actions: [
          IconButton(
            icon: Icon(Icons.history),
            onPressed: () {
              // Handle recent transactions
            },
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Balance Section
            Container(
              padding: EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: containerColors,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Balance',
                        style: TextStyle(fontSize: 16, color: Colors.grey),
                      ),
                      SizedBox(height: 4),
                      Text(
                        isBalanceHidden ? '*****' : '\$${totalBalance.toStringAsFixed(2)}',
                        style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                      ),
                    ],
                  ),
                  IconButton(
                    icon: Icon(isBalanceHidden ? Icons.visibility_off : Icons.visibility),
                    onPressed: toggleBalanceVisibility,
                  ),
                ],
              ),
            ),

            SizedBox(height: 20),

            // Send and User ID Row
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                // Send Button
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: () {
                      // Handle send action
                    },
                    icon: Icon(Icons.send),
                    label: Text('Send'),
                    style: ElevatedButton.styleFrom(
                      padding: EdgeInsets.symmetric(vertical: 40), // Adjust the vertical padding to increase the button height
                      backgroundColor: darkTheme ? Color(0xFF464C64) : Color(0xFFF1B1A28), // Set the background color
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8), // Border radius for rounded corners
                      ),
                    ),
                  ),
                ),

                SizedBox(width: 16),

                // User ID Container
                Expanded(
                  child: Container(
                    padding: EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: darkTheme ? Color(0xFF464C64) : Color(0xFFF1B1A28),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('User ID', style: TextStyle(fontSize: 16, color: Colors.grey)),
                        Text('12345', style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                      ],
                    ),
                  ),
                ),
              ],
            ),

            SizedBox(height: 20),

            // Assets Section
            Text(
              'Assets',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 10),

            // Assets List
            Expanded(
              child: ListView(
                children: [
                  // Virtual Bank Account
                  _buildAssetRow(
                    icon: Icons.account_balance,
                    name: 'Virtual Bank Account',
                    amount: '\$3000.00',
                    onTap: () {
                      navigateToDepositScreen(
                        assetName: 'Virtual Bank Account',
                        walletAddress: 'Bank-Account-123456',
                        network: 'Local Bank',
                      );
                    },
                  ),

                  // Crypto Assets
                  _buildAssetRow(
                    icon: FontAwesomeIcons.bitcoin,
                    name: 'Bitcoin',
                    amount: '0.005 BTC',
                    onTap: () {
                      navigateToDepositScreen(
                        assetName: 'Bitcoin',
                        walletAddress: 'BTC-Address-1A1zP1',
                        network: 'Bitcoin Network',
                        memoId: '',  // Bitcoin doesn't need memo ID
                      );
                    },
                  ),
                  _buildAssetRow(
                    icon: FontAwesomeIcons.ethereum,
                    name: 'Ethereum',
                    amount: '1.2 ETH',
                    onTap: () {
                      navigateToDepositScreen(
                        assetName: 'Ethereum',
                        walletAddress: 'ETH-Address-0x123456',
                        network: 'Ethereum Network',
                        memoId: '',  // Ethereum doesn't need memo ID
                      );
                    },
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // Helper method to build each asset row
  Widget _buildAssetRow({required IconData icon, required String name, required String amount, required VoidCallback onTap}) {
    return GestureDetector(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Row(
          children: [
            Icon(icon, size: 30),
            SizedBox(width: 16),
            Expanded(
              child: Text(name, style: TextStyle(fontSize: 18)),
            ),
            Text(
              isBalanceHidden ? '*****' : amount, // Mask the asset amount if balance is hidden
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
          ],
        ),
      ),
    );
  }
}
