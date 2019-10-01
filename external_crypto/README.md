Ideally, the code in this folder would live in /usr/local/.../libexec/crypto/
(src/bin). Instead, we'll make this directory for it.

Note that liboqs.so should be a symlink (ln -s) to your compiled shared object
file for liboqs (see liboqs installation instructions)

Note to self: Where should this go? Should we separate the OQSSig
 interface from the library functions?
