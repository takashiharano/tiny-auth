package com.takashiharano.auth.tools;

import com.takashiharano.auth.Auth;

public class HashGenerator {

  private static Auth auth;

  public static void main(String args[]) {
    test();
  }

  private static void test() {
    String filePath = "C:/tmp/pass.txt";
    String hashAlgorithm = "SHA-256";
    int stretching = 0;
    auth = new Auth(filePath, hashAlgorithm, stretching);

    String user = "root";
    String pass = "0000";

    String hash = auth.getHashStringForStorage(pass, user);
    System.out.println(user + "\t" + hash);
  }

}
