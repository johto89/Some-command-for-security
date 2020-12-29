#!/usr/bin/python3

from os import getcwd, listdir
from os.path import join, isfile
from time import strftime
from hashlib import md5

def list_files(basedir=None):
    """List only files within the respective directory"""

    if basedir is None:
        basedir = getcwd()

    for item in listdir(basedir):
        path = join(basedir, item)

        if isfile(path):
            yield path


def md5sum(f, block_size=None):
    """Returns the MD5 checksum of the respective file"""

    if block_size is None:
        block_size = 4096

    hash = md5()

    with open(f, 'rb') as fh:
        block = fh.read(block_size)

        while block:
            hash.update(block)
            block = fh.read(block_size)

    return hash.hexdigest()


def md5sums(basedir=None, block_size=None):
    """Yields (<file_name>, <md5sum>) tuples
    for files within the basedir.
    """

    for f in list_files(basedir=basedir):
        yield (f, md5sum(f, block_size=block_size))


if __name__ == '__main__':
    hash_file = strftime('Filehash%Y%m%d-%H%M%S')

    with open(hash_file, 'w') as fh:
        for file_hash in md5sums():
            fh.write('\t'.join(file_hash) + '\n')