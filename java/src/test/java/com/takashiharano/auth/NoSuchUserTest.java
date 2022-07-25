package com.takashiharano.auth;

public class NoSuchUserTest {

  private static Auth auth;

  public static void main(String args[]) {
    String filePath = "C:/tmp/pass.txt";
    String algorithm = "SHA-256";
    int stretching;

    String[] userIds = { "user1", "user2" };

    stretching = 0;
    auth = new Auth(filePath, algorithm, stretching);
    registerTest();
    test1(stretching);

    stretching = 1;
    deleteTest(userIds);
    auth = new Auth(filePath, algorithm, stretching);
    registerTest();
    test1(stretching);

    stretching = 2;
    deleteTest(userIds);
    auth = new Auth(filePath, algorithm, stretching);
    registerTest();
    test1(stretching);

    stretching = 100000;
    deleteTest(userIds);
    auth = new Auth(filePath, algorithm, stretching);
    registerTest();
    test1(stretching);
  }

  private static void registerTest() {
    auth.registerByPlainPass("user1", "1111");
    auth.registerByPlainPass("user2", "2222", "");
  }

  private static void deleteTest(String[] userIds) {
    for (int i = 0; i < userIds.length; i++) {
      String id = userIds[i];
      auth.remove(id);
    }
  }

  private static void test1(int stretching) {
    log("");
    log("-- stretching = " + stretching + " --");

    // NO_SUCH_USER
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
