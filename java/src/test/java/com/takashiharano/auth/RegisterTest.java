package com.takashiharano.auth;

public class RegisterTest {

  private static Auth auth;

  public static void main(String args[]) {
    test();
  }

  private static void test() {
    String filePath = "C:/tmp/pass.txt";
    String user = "user1";
    String pass = "1111";
    String hashAlgorithm = "SHA-256";
    int stretchingN = 0;

    auth = new Auth(filePath, hashAlgorithm, stretchingN);
    int result = auth.registerByPlainPass(user, pass);
    System.out.println("result = " + result);
  }

}
