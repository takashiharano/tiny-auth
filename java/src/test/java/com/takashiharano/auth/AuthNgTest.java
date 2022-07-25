package com.takashiharano.auth;

public class AuthNgTest {

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
    log("-- TEST1 - " + stretching + " --");

    String user;
    String pass;
    String hash;
    String salt;

    // NG
    user = "user1";
    pass = "2222";
    salt = user;
    hash = auth.getHashString(pass, salt);
    log("hash = " + hash);
    log("PASSWORD_MISMATCH:" + auth.auth(user, hash));
    log("");

    user = "user2";
    pass = "1111";
    salt = user;
    hash = auth.getHashString(pass);
    log("hash = " + hash);
    log("PASSWORD_MISMATCH" + auth.auth(user, hash));
    log("");

    // Update/NG
    pass = "1111";
    salt = user;
    auth.registerByPlainPass(user, pass);
    hash = auth.getHashString("0000", salt);
    log("hash = " + hash);
    log("PASSWORD_MISMATCH:" + auth.auth(user, hash));
    log("");
  }

  public static void log(String msg) {
    System.out.println(msg);
  }

}
