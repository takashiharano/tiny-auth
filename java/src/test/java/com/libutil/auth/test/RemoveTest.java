package com.libutil.auth.test;

import com.libutil.auth.Auth;

public class RemoveTest {

  private static Auth auth;

  public static void main(String args[]) {
    test();
  }

  private static void test() {
    String filePath = "C:/tmp/pass.txt";
    String user = "user1";

    auth = new Auth(filePath);
    boolean removed = auth.remove(user);
    System.out.println(removed);
  }

}
