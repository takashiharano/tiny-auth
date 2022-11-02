package com.libutil.auth.test;

import com.libutil.auth.Authenticator;

public class TestManager {

  private static Authenticator auth;

  public static Authenticator initAuth() {
    int stretching = 1;

    System.out.println("stretching=" + stretching);

    String filePath = "C:/tmp/pass.txt";
    String hashAlgorithm = "SHA-256";
    auth = new Authenticator(filePath, hashAlgorithm, stretching);
    return auth;
  }

}
