import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import auth

filePath = 'C:/test/pass.txt';
algorithm = 'SHA-256';

def log(m):
  print(m)

# Regoster Test
def register_test(stretching):
  global filePath
  global algorithm

  log('-- REGISTER TEST - ' + str(stretching) + ' --')
  auth.init(filePath, algorithm, stretching)
  auth.register_by_plain_pass('user1', '1111') # w/ salt (id)
  auth.register_by_plain_pass('user2', '2222', '') # w/o salt
  log('OK')
  log('')

# Delete Test
def delete_test(user_list):
  global filePath
  global algorithm

  log('-- DELETE TEST --')
  auth.init(filePath, algorithm, 0)

  for i in range(len(user_list)):
    id = user_list[i]
    auth.delete_user(id)

  log('OK')
  log('')

# Test1
def test1(stretching):
  global filePath
  global algorithm

  log('-- TEST1 - ' + str(stretching) + ' --')
  auth.init(filePath, algorithm, stretching)

  # OK
  user = 'user1'
  pw = '1111'
  salt = user
  hash = auth.get_hash(pw, salt)
  log('hash = ' + hash)
  log('OK:' + auth.auth(user, hash))

  user = 'user2'
  pw = '2222'
  salt = user
  hash = auth.get_hash(pw)
  log('hash = ' + hash)
  log('OK:' + auth.auth(user, hash))

  # Update/OK
  pw = '0000'
  auth.register_by_plain_pass(user, pw)
  salt = user
  hash = auth.get_hash(pw, salt)
  log('hash = ' + hash)
  log('OK:' + auth.auth(user, hash))

  # NG
  log('');
  user = 'user1';
  pw = '2222';
  hash = auth.get_hash(pw, salt);
  log('hash = ' + hash);
  log('NG:' + auth.auth(user, hash));

  user = 'user2';
  pw = '1111';
  salt = user
  hash = auth.get_hash(pw);
  log('hash = ' + hash);
  log('NG:' + auth.auth(user, hash));

  # Update/NG
  pw = '1111'
  auth.register_by_plain_pass(user, pw)
  salt = user
  hash = auth.get_hash('0000', salt)
  log('hash = ' + hash)
  log('OK:' + auth.auth(user, hash))

  # NO_SUCH_USER
  log('');
  user = 'user3';
  pw = '3333';
  hash = auth.get_hash(pw, salt);
  log('hash = ' + hash);
  log('NO_SUCH_USER:' + auth.auth(user, hash));

# Test
def test(stretching):
  delete_test(['user1', 'user2']);
  register_test(stretching)
  test1(stretching)
  log('')

def main():
  test(0)
  test(1)
  test(2)
  test(100000)

main()
