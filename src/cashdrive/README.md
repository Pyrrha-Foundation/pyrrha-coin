# Cashdrive

Cashdrive uses a bitwise trie to store the UTXO set in a structure that is deterministic, parallelizable, persistent, and authenticated.

This implementation of cashdrive wraps around leveldb using the leveldb database to hold all information. All data on disk and in the memory cache is managed by leveldb. It is based on an in-memory implementation written in C. The source code for which is located at https://gitlab.com/ggriffith/bitwise-trie
