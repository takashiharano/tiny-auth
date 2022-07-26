package com.libutil.auth.test;

import com.libutil.auth.Auth;

public class AuthOkTest {

  private static Auth auth;

  public static void main(String args[]) {
    test();
  }

  public static void test() {
    auth = TestManager.initAuth();

    authByPlainPass("user1", "1111");
    authByPlainPass("user2", "2222");

    authByHash("user1", "1111");
    authByHash("user2", "2222");
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
