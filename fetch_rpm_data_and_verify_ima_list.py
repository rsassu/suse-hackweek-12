#! /usr/bin/python

# fetch_rpm_data_and_verify_ima_list.py: extract digests from RPMs and verify an IMA list
#
# Author: Roberto Sassu <rsassu@suse.de>

import os
import sys
import struct
import gevent
from gevent import monkey

monkey.patch_all()

import httplib

repos = [
'/update/13.2/',
'/distribution/13.2/repo/oss/suse',
'/update/13.2-non-oss/',
'/distribution/13.2/repo/non-oss/suse',
]

digests = []

def init_connection(server):
    return httplib.HTTPConnection(server)


def fetch_data(conn, relative_path, arch, pkg_filename, url_offset, size):
    for repo in repos:
        conn.request("GET", '%s/%s/%s/%s' % (relative_path, repo, arch, pkg_filename),
                     headers={'Range': 'bytes=%s-%s' % (url_offset, url_offset + size),
                              'Connection': 'keep-alive'})
        resp = conn.getresponse()
        data = resp.read()
        if resp.status == 206:
            return data

    return ''


def get_next_header_offset(num_header_entries, header_data_size):
    next_header_offset = 16 + 16 * num_header_entries + header_data_size
    next_header_offset += next_header_offset % 8
    return next_header_offset


def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def main(server, relative_path, packages):
    conn = init_connection(server)
    total_packages = len(packages)
    count = 1

    for pkg in packages:
        #print 'Processing (%d/%d): %s' % (count, total_packages, pkg)

        pkg_arch = pkg.split('.')[-1]
        rpm_str = fetch_data(conn, relative_path, pkg_arch, '%s.rpm' % pkg, 96, 6000)
        if len(rpm_str) == 0:
            print 'Error: %s - signature header' % pkg
            continue

        offset = 0

        # signature header
        num_header_entries = struct.unpack('!i', rpm_str[8:12])[0]
        header_data_size = struct.unpack('!i', rpm_str[12:16])[0]
        offset += get_next_header_offset(num_header_entries, header_data_size)
        rpm_str = rpm_str[offset:]

        # main header
        num_header_entries = struct.unpack('!i', rpm_str[8:12])[0]
        header_data_size = struct.unpack('!i', rpm_str[12:16])[0]
        offset += 16
        rpm_str = rpm_str[16:]

        file_digest_entry = None
        for i in xrange(0, num_header_entries):
            file_digest_entry = struct.unpack('!iiii', rpm_str[i * 16:i * 16 + 16])
            if file_digest_entry[0] == 1035:
                break

        if file_digest_entry is None:
            print 'Error - digests: %s' % pkg
            continue

        digests_data_offset = num_header_entries * 16 + file_digest_entry[2]
        digests_data_length = file_digest_entry[3] * 33
        if len(rpm_str) <  digests_data_offset + digests_data_length:
            rpm_str = fetch_data(conn, relative_path, pkg_arch, '%s.rpm' % pkg, 96 + offset + digests_data_offset, digests_data_length)
            if len(rpm_str) == 0:
                print 'Error: %s - file digests' % pkg
        else:
            rpm_str = rpm_str[digests_data_offset:]

        for i in xrange(0, file_digest_entry[3]):
            a = struct.unpack('33s', rpm_str[0:33])[0]
            if a[0] == '\0':
                a = ''
                rpm_str = rpm_str[1:]
            else:
                rpm_str = rpm_str[33:]
                digests.append(a[:-1])

        count += 1


# syntax: ./fetch_rpm_data_and_verify_ima_list.py <repository server> <repository relative path> <IMA measurements> <output of 'rpm -qa'>
if __name__ == '__main__':
    # create a database of known digest values
    jobs = [gevent.spawn(main, sys.argv[1], sys.argv[2], pkgs) for pkgs in list(chunks(sys.argv[4:], 25))]
    gevent.joinall(jobs)

    # check the IMA file list and display the lines with digests not recognized
    fd = open(sys.argv[3], 'r')
    report = fd.read()
    fd.close()
    for line in report.split('\n')[:-1]:
        if line.split()[3][:32] not in digests:
            print line
