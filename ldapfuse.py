#!/usr/bin/env python2
import fuse
import ldap

import stat
import os
import errno
import sys
from urlparse import urlparse

import time
import yaml

fuse.fuse_python_api = (0, 2)

class LDAP:
  def __init__(self, url):
    self.ldap_retry = 15
    self.cache_timeout = 10
    self.grace = 3600

    self.url = url
    self.next_try = 0
    self.down = False
    self.cache = {}
    self.config = None
    try:
      config = yaml.safe_load(file('/etc/ldapfuse.conf'))
      self.config = config[self.url.path[1:]]
    except (IOError, KeyError):
      pass

  def search(self, dn):
    return self._search(dn, ldap.SCOPE_BASE)

  def search_level(self, dn):
    return self._search(dn, ldap.SCOPE_ONELEVEL)

  def _search(self, dn, scope):
    # If down, use cache value if still within grace period
    if self.down and self.next_try > time.time():
      if dn in self.cache and scope in self.cache[dn] and \
          self.cache[dn][scope]['timeout'] + self.grace > time.time():
        print "down, using cache"
        return (self.cache[dn][scope]['result'],
                self.cache[dn][scope]['protected'])
      else:
        print "down, no cache"
        return None, None

    try:
      # Use cache value if not too old
      if dn in self.cache and scope in self.cache[dn] and \
          self.cache[dn][scope]['timeout'] > time.time():
        print "up, using cache"
        return (self.cache[dn][scope]['result'],
                self.cache[dn][scope]['protected'])

      print "refresh"
      con = ldap.initialize(self.url.scheme + '://' + self.url.netloc)

      sr = con.search_st(dn, scope, timeout=1)

      # If we have access to an authenticated user, do the search twice
      # and all extra attributes should be root only.
      secret_sr = sr
      if self.config:
        # Reconnect
        con.unbind()
        con = ldap.initialize(self.url.scheme + '://' + self.url.netloc)
        con.simple_bind_s(self.config['who'], self.config['credentials'])

        secret_sr = con.search_st(dn, scope, timeout=1)

      # Compute secret status
      public_attrs = {dn: set(attrs.keys()) for (dn, attrs) in sr}
      secret_attrs = {dn: set(attrs.keys()) for (dn, attrs) in secret_sr}
      # Assume that secret_attrs have at least as many DNs as public_attr
      protect_attrs = {dn: attrs - public_attrs[dn] for (dn, attrs) in
                       secret_attrs.iteritems()}

      if not dn in self.cache:
        self.cache[dn] = {}

      if not scope in self.cache[dn]:
        self.cache[dn][scope] = {}

      self.cache[dn][scope]['timeout'] = time.time() + self.cache_timeout
      self.cache[dn][scope]['result'] = secret_sr
      self.cache[dn][scope]['protected'] = protect_attrs

      self.down = False
      return secret_sr, protect_attrs
    except ldap.LDAPError:
      self.down = True
      self.next_try = time.time() + self.ldap_retry

      import traceback
      traceback.print_exc()

      # Use cache value if still within grace period
      if dn in self.cache and scope in self.cache[dn] and \
          self.cache[dn][scope]['timeout'] + self.grace > time.time():
        print "downed, using cache"
        return (self.cache[dn][scope]['result'],
                self.cache[dn][scope]['protected'])
      else:
        print "downed, no cache"
        return None, None

class LdapFS(fuse.Fuse):
  def __init__(self, url):
    fuse.Fuse.__init__(self)
    self.url = url
    self.ldap = LDAP(url)

  # return dn, attrib from path
  def _resolve(self, path, base):
    path = path[1:]
    if path == '':
      return base, None

    last = path.split('/')[-1]
    
    rdn = ','.join(filter(lambda x: "=" in x, reversed(path.split('/'))))
    if rdn == '':
      dn = base
    else:
      dn = rdn + ',' + base
    return dn, None if '=' in last else last

  def _format_attrib(self, attrib):
    return "\n".join(attrib)

  def readdir(self, path, offset):
    dn, attrib = self._resolve(path, url.path[1:])

    for r in '.', '..':
      yield fuse.Direntry(r)

    directories, _ = self.ldap.search_level(dn)
    for i in directories:
      yield fuse.Direntry(i[0].split(',')[0])

    files, _ = self.ldap.search(dn)
    for i in files[0][1]:
      yield fuse.Direntry(i)

  def getattr(self, path):
    """
    - st_mode (protection bits)
    - st_ino (inode number)
    - st_dev (device)
    - st_nlink (number of hard links)
    - st_uid (user ID of owner)
    - st_gid (group ID of owner)
    - st_size (size of file, in bytes)
    - st_atime (time of most recent access)
    - st_mtime (time of most recent content modification)
    - st_ctime (platform dependent; time of most recent metadata change on Unix,
          or the time of creation on Windows).
    """

    print '*** getattr', path

    class Stat():
      st_mode = 0
      st_ino = 0
      st_dev = 0
      st_nlink = 0
      st_uid = 0
      st_gid = 0
      st_size = 0
      st_atime = 0
      st_mtime = 0
      st_ctime = 0

    st = Stat()

    dn, attrib = self._resolve(path, url.path[1:])
    print dn, attrib

    # Try to update fetch fresh data
    sr, protected = self.ldap.search(dn)
    if sr == None:
      return -errno.ENOENT

    # dir (dn)
    if not attrib:
      st.st_mode = stat.S_IFDIR | 0755
      st.st_nlink = 2
      return st
    # attribute
    elif attrib in sr[0][1]:
      if attrib in protected[dn]:
        st.st_mode = stat.S_IFREG | 0400
      else:
        st.st_mode = stat.S_IFREG | 0444
      st_st_nlink = 1
      st.st_size = len(self._format_attrib(sr[0][1][attrib]))
      return st

    return -errno.ENOENT

  def getdir(self, path):
    """
    return: [[('file1', 0), ('file2', 0), ... ]]
    """

    print '*** getdir', path
    return -errno.ENOSYS

  def open ( self, path, flags ):
    print '*** open', path, flags
    dn, attrib = self._resolve(path, url.path[1:])
    # Try to update fetch fresh data
    sr, _ = self.ldap.search(dn)
    if sr == None:
      return -errno.ENOENT

    if attrib in sr[0][1]:
      if flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) != os.O_RDONLY:
        return -errno.EACCES
    else:
      return -errno.ENOENT

    return 0

  def read ( self, path, length, offset ):
    print '*** read', path, length, offset
    dn, attrib = self._resolve(path, url.path[1:])
    # Try to update fetch fresh data
    sr, _ = self.ldap.search(dn)
    if sr == None:
      return -errno.ENOENT

    if attrib in sr[0][1]:
      data = self._format_attrib(sr[0][1][attrib])
      return data[offset:offset+length]
    else:
      return -errno.ENOENT

if __name__ == '__main__':
  url = urlparse(sys.argv[1])
  fs = LdapFS(url)
  fs.parse(sys.argv[2:] + [
    '-osubtype=ldapfuse,default_permissions,fsname=' + url.netloc], errex=1)
  fs.main()
