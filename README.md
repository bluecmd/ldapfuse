# ldapfuse
Python FUSE module used for mounting an LDAP base

## Example

Add this to your /etc/fstab:

    ldapfuse.py#ldaps://my.ldap.server/dc=domain,dc=tld  /ldap   fuse    noauto,allow_other      0     0

## sshd configuration
By doing something like:

    AuthorizedKeysFile      "/ldap/ou=people/cn=%u/sshPublicKey"

in your sshd_config you can allow users to have their SSH public keys in LDAP. Works very well with GOsa2 (https://oss.gonicus.de/labs/gosa)
