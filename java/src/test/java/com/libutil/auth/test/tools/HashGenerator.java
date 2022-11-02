package com.libutil.auth.test.tools;

import com.libutil.auth.Authenticator;

public class HashGenerator {

  private static Authenticator auth;

  public static void main(String args[]) {
    test();
  }

  private static void test() {
    String filePath = "C:/tmp/pass.txt";
    String hashAlgorithm = "SHA-256";
    int stretching = 1;
    auth = new Authenticator(filePath, hashAlgorithm, stretching);

    String user = "root";
    String pass = "0000";

    String hash = auth.getHashStringForStorage(pass, user);
    System.out.println(user + "\t" + hash);
  }

}
