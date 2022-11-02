package com.libutil.auth.test;

import com.libutil.auth.Authenticator;

public class NoSuchUserTest {

  private static Authenticator auth;

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
