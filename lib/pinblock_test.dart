import 'package:prueba/pinblock.dart';
import 'package:test/test.dart';

void main() {
  test('create document block', () {
    PinBlock pinBlock = PinBlock();
    expect(
        pinBlock.createDocumentBlock('12345678'), equals('0000000012345678'));
    expect(pinBlock.createDocumentBlock('123456789012'),
        equals('0000123456789012'));
    expect(pinBlock.createDocumentBlock('12345678901234'),
        equals('0000345678901234'));
  });

  test('create password block', () {
    PinBlock pinBlock = PinBlock();
    expect(pinBlock.createPasswordBlock('1234'), equals('041234FFFFFFFFFF'));
  });

  test('create otp block', () {
    PinBlock pinBlock = PinBlock();
    expect(pinBlock.createOtpBlock('123456'), equals('06123456FFFFFFFF'));
  });

  test('create account block', () {
    PinBlock pinBlock = PinBlock();
    String bin = "400478";
    String account = "03003193435";
    expect(
        pinBlock.createAccountBlock(bin, account), equals('0000803003193435'));
  });

  test('convert hex to bytes and bytes to hex', () {
    PinBlock pinBlock = PinBlock();
    List<int> bytes = pinBlock.hexToBytes("0000803003193435");

    expect(pinBlock.bytesToHex(bytes), equals('0000803003193435'));
  });

  test('xor bytes chain', () {
    PinBlock pinBlock = PinBlock();
    List<int> document = pinBlock.hexToBytes("0000123456789012");
    List<int> password = pinBlock.hexToBytes("041234FFFFFFFFFF");
    expect(pinBlock.xor(document, password), equals('041226CBA9876FED'));
  });

  test('xor bytes chain', () {
    PinBlock pinBlock = PinBlock();
    String modulus =
        "be1f1a241debd751f67ff6d7c28b69779ebdcdd7e0e299ccc72e4ffaf21fe53587a09bc43f8e8cef4d5024e7ee159bd4d0e893bbd3939f17b4db5e049686cd20bedc754cdd2d2f28e24042030109f723e0fac1333b0cfafd52a281b481b2c5ba6823a6b82252a1a9d5fedebd3078904281ce3326fab40ebfbb370baee0dd478659481d1c6ee369a0d72b866f9af1e9327a003c4a6d2fe2c5fe861ceab4dde2de4edb41070229c60099f2779fc7302138c273728801163a1b560acb78da10042e702331d70a2b0300206885b6cf8bbe0b23c11d162383f43564ecf50e78b05a79ed61245a2093f14f92215029b0bf6f8356d270d3f08f0ee55dddfc25cb78e61f";
    String exponent = "10001";
    expect(
        pinBlock.rsaEncrypt(modulus, exponent, '041226CBA9876FED'), isNotNull);
  });

  test('complete login encrypt', () {
    PinBlock pinBlock = PinBlock();
    String userId = "1007236222";
    String password = "1739";
    String modulus =
        "876e40396e4680104bf58cd17479ea2854de6f3984751e3a1c48cdf293f2c914ddf0b5050c2e2c7930db57a60f6d04eef312f6ef909f6c31a27c96b22c24cdaf64fd18d5774b960456f48663fba4fc95351b2043b381b5df8c6bcbce85b625f79661e5c079c249833e9ddb489d655e7be302db8b67765402d0cfdbb2e0301d729db349a1ecd1bf4e7958cfdcf74e1be0e9c7d05a9bf0b77350215c6853f5ad5e2a0343d0adf0659af35bfd99bdf98f53ab5c1649327a1d971f4092ae84644a5edbbe9b6dd936a5cbbd0248a8ab143deaa8836a7b6ece97cb8ff07ac529122fc2b03cbbc9324c26d73fbf7be96730a86e4fd5bd4d4dcb41de8682d44540c3ca05";
    String exponent = "10001";
    String pin = pinBlock.loginEncrypt(userId, password, modulus, exponent);
    print(pin);
    print(pin.length);
    expect(pinBlock.loginEncrypt(userId, password, modulus, exponent),
        equals('expected'));
  });

  test('complete otp encrypt', () {
    PinBlock pinBlock = PinBlock();
    String bin = "400478";
    String account = "03003193435";
    String pin = "123456";
    String modulus =
        "be1f1a241debd751f67ff6d7c28b69779ebdcdd7e0e299ccc72e4ffaf21fe53587a09bc43f8e8cef4d5024e7ee159bd4d0e893bbd3939f17b4db5e049686cd20bedc754cdd2d2f28e24042030109f723e0fac1333b0cfafd52a281b481b2c5ba6823a6b82252a1a9d5fedebd3078904281ce3326fab40ebfbb370baee0dd478659481d1c6ee369a0d72b866f9af1e9327a003c4a6d2fe2c5fe861ceab4dde2de4edb41070229c60099f2779fc7302138c273728801163a1b560acb78da10042e702331d70a2b0300206885b6cf8bbe0b23c11d162383f43564ecf50e78b05a79ed61245a2093f14f92215029b0bf6f8356d270d3f08f0ee55dddfc25cb78e61f";
    String exponent = "10001";
    expect(pinBlock.pinOtpEncrypt(bin, account, pin, modulus, exponent),
        isNotNull);
  });
}
