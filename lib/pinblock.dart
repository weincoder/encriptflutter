import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/asymmetric/api.dart';

class PinBlock{
  static const int LENGTH = 12;
  static const int MAX_LENGTH = 16;
  static const String FILL_NUM = "0";
  static const String FILL_CHAR = "F";
  static const String LENGTH_PIN = "04";
  static const String LENGTH_OTP = "06";

  String createDocumentBlock(String numDoc){
    String numDocBlock = numDoc;
    if(numDoc.length > LENGTH){
      numDocBlock = numDoc.substring(numDoc.length-LENGTH);
    }
    return numDocBlock.padLeft(MAX_LENGTH, FILL_NUM);
  }

  String createPasswordBlock(String password){
    String passBlock = LENGTH_PIN + password;
    return passBlock.padRight(MAX_LENGTH, FILL_CHAR);
  }

  String createOtpBlock(String password){
    String passBlock = LENGTH_OTP + password;
    return passBlock.padRight(MAX_LENGTH, FILL_CHAR);
  }

  String createAccountBlock(String bin, String account){
    String blockString = bin + account;
    if (blockString.length > 12) {
      blockString = blockString.substring(blockString.length-LENGTH);
    }
    return blockString.padLeft(MAX_LENGTH, FILL_NUM);
  }

  List<int> hexToBytes(String data){
    return hex.decode(data);
  }

  String bytesToHex(List<int> bytes){
    return hex.encode(bytes);
  }

  String xor(List<int> bytesOne, List<int> bytesTwo){
    List<int> converted = List<int>();
    for(int i = 0; i < bytesOne.length; i++){
      converted.add(bytesOne[i]^bytesTwo[i]);
    }
    return bytesToHex(converted).toUpperCase();
  }

  String rsaEncryptX(String modulus, String exponent, String data){
    final publicKey = RSAPublicKey(BigInt.parse('0x'+modulus),
        BigInt.parse('0x'+exponent));
    final encrypter = Encrypter(RSA(publicKey: publicKey));
    Uint8List encrypted = encrypter.encrypt(data).bytes;
    return bytesToHex(encrypted).toUpperCase();
  }

  String rsaEncrypt(String modulus, String exponent, String data){
    final publicKey = RSAPublicKey(BigInt.parse('0x'+modulus),
        BigInt.parse('0x'+exponent));

    final encrypter = Encrypter(RSA(publicKey: publicKey, encoding: RSAEncoding.OAEP));
    Uint8List encrypted = encrypter.encrypt(data).bytes;
    return bytesToHex(encrypted).toUpperCase();
  }

  String loginEncrypt(String userID, String pass, String modulus,
      String exponent){
    String docBlk = createDocumentBlock(userID);
    String pasBlk = createPasswordBlock(pass);
    String pinBlock = xor(hexToBytes(docBlk), hexToBytes(pasBlk));
    return rsaEncrypt(modulus, exponent, pinBlock);
  }

  String pinOtpEncrypt(String bin, String account, String pin, String modulus,
      String exponent){
    String accountBlk = createAccountBlock(bin, account);
    String pinBlk = createOtpBlock(pin);
    String pinBlkOtp = xor(hexToBytes(accountBlk), hexToBytes(pinBlk));
    return rsaEncrypt(modulus, exponent, pinBlkOtp);
  }
}