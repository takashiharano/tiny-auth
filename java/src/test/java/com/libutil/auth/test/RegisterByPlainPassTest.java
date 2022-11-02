package com.libutil.auth.test;

import com.libutil.auth.Authenticator;

public class RegisterByPlainPassTest {

  private static Authenticator auth;

  public static void main(String args[]) {
    test();
  }

  public static void test() {
    auth = TestManager.initAuth();

    register("user1", "1111");
    register("user2", "2222");
  }

  private static void register(String user, String pass) {
    int result = auth.registerByPlainPass(user, pass);
    System.out.println("register: user=" + user + " result=" + result);
  }

}
