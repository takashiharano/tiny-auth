package com.libutil.auth.test;

import com.libutil.auth.Authenticator;

public class AuthNgTest {

  private static Authenticator auth;

  public static void main(String args[]) {
    test();
  }

  public static void test() {
    auth = TestManager.initAuth();

    authByPlainPass("user1", "2222");
    authByPlainPass("user2", "1111");

    authByHash("user1", "2222");
    authByHash("user2", "1111");
  }

  private static void authByPlainPass(String user, String pass) {
    String result = auth.authByPlainPass(user, pass);
    System.out.println("auth by plain: user=" + user + " result=" + result);
  }

  private static void authByHash(String user, String pass) {
    String hash = auth.getHashString(pass, user);
    String result = auth.auth(user, hash);
    System.out.println("auth by hash : user=" + user + " result=" + result);
  }

}
