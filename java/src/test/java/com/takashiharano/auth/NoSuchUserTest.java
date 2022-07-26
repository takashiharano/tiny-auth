package com.takashiharano.auth;

public class NoSuchUserTest {

  private static Auth auth;

  public static void main(String args[]) {
    test();
  }

  private static void test() {
    auth = TestManager.initAuth();

    String user = "user3";
    String pass = "3333";
    String salt = user;
    String hash = auth.getHashString(pass, salt);
    log("hash = " + hash);
    log("NO_SUCH_USER:" + auth.auth(user, hash));
  }

  public static void log(String msg) {
    System.out.println(msg);
  }

}
