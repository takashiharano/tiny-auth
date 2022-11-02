package com.libutil.auth.test;

import com.libutil.auth.Authenticator;

public class RemoveTest {

  private static Authenticator auth;

  public static void main(String args[]) {
    test();
  }

  private static void test() {
    String filePath = "C:/tmp/pass.txt";
    String user = "user1";

    auth = new Authenticator(filePath);
    boolean removed = auth.remove(user);
    System.out.println(removed);
  }

}
