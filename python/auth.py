# TinyAuth
# Copyright 2020 Takashi Harano
# Released under the MIT license
# https://github.com/takashiharano/tiny-auth

import os
import sys
import hashlib

LINE_SEPARATOR = os.linesep
DELIMITER = '\t'
DEFAULT_ENCODING = 'utf-8'

pass_file_path = ''
hash_algorithm = 'SHA-256'
stretching = 1

# Initlalize the module
def init(file_path, algorithm='SHA-256', stretching_n=0):
    global pass_file_path
    global hash_algorithm
    global stretching
    pass_file_path = file_path
    hash_algorithm = algorithm
    stretching = stretching_n

# Authentication
def auth(id, hash):
    records = load_password_file()

    for i in range(len(records)):
        record = records[i]
        fields = record.split(DELIMITER)
        if len(fields) < 2:
            continue
        uid = fields[0]
        user_hash = fields[1]
        if uid == id:
            stretched_hash = stretch(hash, stretching)
            if stretched_hash == user_hash:
                return 'OK'
            else:
                return 'NG'

    return 'NO_SUCH_USER'

# Register a password
def register(id, hash):
    global stretching
    hash = stretch(hash, stretching)
    new_record = id + DELIMITER + hash
    records = load_password_file()

    new_records = ''
    found = False
    for i in range(len(records)):
        record = records[i]
        fields = record.split(DELIMITER)
        uid = fields[0]
        if uid == id:
            found = True
            new_records += new_record + LINE_SEPARATOR
        else:
            new_records += record + LINE_SEPARATOR

    if not found:
        new_records += new_record + LINE_SEPARATOR

    save_password_file(new_records)

# Register a password with plain text
# id: user id
# pw: plain password
# salt: salt for hash. Set '' not to use salt / None=id
def register_by_plain_pass(id, pw, salt=None):
    if salt is None:
        salt = id
    hash = get_hash(pw, salt)
    register(id, hash)

# Delete a user record
def delete_user(id):
    records = load_password_file()
    new_records = ''
    deleted = False
    for i in range(len(records)):
        record = records[i]
        fields = record.split(DELIMITER)
        uid = fields[0]
        if uid == id:
            deleted = True
        else:
            new_records += record + LINE_SEPARATOR
    save_password_file(new_records)
    return deleted

# Save passrowd file
def save_password_file(records):
    global pass_file_path
    write_text_file(pass_file_path, records)

# Hash
def get_hash(src, salt='', algorithm='SHA-256'):
    m = None

    if algorithm == 'SHA-256':
        m = hashlib.sha256()
    elif algorithm == 'SHA-512':
        m = hashlib.sha512()
    elif algorithm == 'SHA-224':
        m = hashlib.sha224()
    elif algorithm == 'SHA-384':
        m = hashlib.sha384()
    elif algorithm == 'SHA-1':
        m = hashlib.sha1()
    elif algorithm == 'MD5':
        m = hashlib.md5()
    # Python 3.6+
    elif algorithm == 'SHA3-256':
        m = hashlib.sha3_256()
    elif algorithm == 'SHA3-512':
        m = hashlib.sha3_512()
    elif algorithm == 'SHA3-224':
        m = hashlib.sha3_224()
    elif algorithm == 'SHA3-384':
        m = hashlib.sha3_384()

    if m is None:
        return ''

    if typename(src) == 'str':
        src += salt
        src = src.encode()

    m.update(src)
    return m.hexdigest()

def stretch(src, n):
    hash = src
    for i in range(n):
        hash = get_hash(hash)
    return hash

def load_password_file():
    global pass_file_path
    records = read_text_file_as_list(pass_file_path)
    return records

# Read Text File
def read_text_file(path, encoding=DEFAULT_ENCODING):
    # f = TextIOWrapper
    f = open(path, 'r', encoding=encoding)
    text = f.read()
    f.close()
    return text

# Read Text File as List
def read_text_file_as_list(path, default=[], encoding=DEFAULT_ENCODING):
    text_list = default
    if os.path.exists(path):
        text = read_text_file(path, encoding=encoding)
        text_list = text2list(text)
        if len(text_list) == 1 and text_list[0] == '':
            text_list = default
    return text_list

# Write Text File
def write_text_file(path, text, encoding=DEFAULT_ENCODING):
    if typename(text) == 'list':
        text = list2text(text)
    b = text.encode()
    f = open(path, 'wb')
    f.write(b)
    f.close()

# line1
# line2
# line3
# -> ['line1', 'line2', 'line3']
def text2list(text):
    text = convert_newline(text, LINE_SEPARATOR)
    a = text.split(LINE_SEPARATOR)
    if len(a) >= 2 and a[-1] == '':
        del a[-1]
    return a

# ['item1', 'item2', 'item3']
# ->
# item1
# item2
# item3
def list2text(arr, line_sep=LINE_SEPARATOR):
    text = ''
    for i in range(len(arr)):
        text += arr[i] + line_sep
    return text

def typename(obj):
    return type(obj).__name__

def convert_newline(s, nl):
    return s.replace('\r\n', '\n').replace('\r', '\n').replace('\n', nl)
