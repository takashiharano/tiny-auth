package com.takashiharano.auth;

public class AuthOkTest {

  private static Auth auth;

  public static void main(String args[]) {
    String filePath = "C:/tmp/pass.txt";
    String algorithm = "SHA-256";
    int stretching;

    String[] userIds = { "user1", "user2" };

    stretching = 0;
    auth = new Auth(filePath, algorithm, stretching);
    register();
    test1(stretching);

    stretching = 1;
    remove(userIds);
    auth = new Auth(filePath, algorithm, stretching);
    register();
    test1(stretching);

    stretching = 2;
    remove(userIds);
    auth = new Auth(filePath, algorithm, stretching);
    register();
    test1(stretching);

    stretching = 10000;
    remove(userIds);
    auth = new Auth(filePath, algorithm, stretching);
    register();
    test1(stretching);
  }

  private static void register() {
    auth.registerByPlainPass("user1", "1111");
    auth.registerByPlainPass("user2", "2222", "");

    // String user = "user2";
    // String pass = "2222";
    // String hash = auth.getHashString(pass);
    // auth.register(user, hash);
  }

  private static void remove(String[] userIds) {
    for (int i = 0; i < userIds.length; i++) {
      String id = userIds[i];
      auth.remove(id);
    }
  }

  private static void test1(int stretching) {
    log("");
    log("-- TEST1 - " + stretching + " --");

    String user;
    String pass;
    String hash;
    String salt;

    // OK
    user = "user1";
    pass = "1111";
    salt = user;
    hash = auth.getHashString(pass, salt);
    log("hash = " + hash);
    log("OK:" + auth.auth(user, hash));
    log("");

    user = "user2";
    pass = "2222";
    salt = user;
    hash = auth.getHashString(pass);
    log("hash = " + hash);
    log("OK:" + auth.auth(user, hash));
    log("");

    // Update/OK
    pass = "0000";
    salt = user;
    auth.registerByPlainPass(user, pass);
    hash = auth.getHashString(pass, salt);
    log("hash = " + hash);
    log("OK:" + auth.auth(user, hash));
  }

  public static void log(String msg) {
    System.out.println(msg);
  }

}
