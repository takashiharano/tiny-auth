package com.takashiharano.auth;

public class TestManager {

  private static Auth auth;

  public static Auth initAuth() {
    int stretching = 1;

    System.out.println("stretching=" + stretching);

    String filePath = "C:/tmp/pass.txt";
    String hashAlgorithm = "SHA-256";
    auth = new Auth(filePath, hashAlgorithm, stretching);
    return auth;
  }

}
