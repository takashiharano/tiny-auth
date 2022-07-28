package com.libutil.auth.test;

import com.libutil.auth.Auth;

public class RegisterByHashTest {

  private static Auth auth;

  public static void main(String args[]) {
    test();
  }

  public static void test() {
    auth = TestManager.initAuth();

    register("user1", "1111");
    register("user2", "2222");
  }

  private static void register(String user, String pass) {
    String hash = auth.getHashString(pass, user);
    int result = auth.registerByHash(user, hash);
    System.out.println("register: user=" + user + " result=" + result);
  }

}