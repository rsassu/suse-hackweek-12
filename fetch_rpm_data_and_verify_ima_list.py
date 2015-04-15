#! /usr/bin/python

# fetch_rpm_data_and_verify_ima_list.py: extract digests from RPMs and verify an IMA list
#
# Author: Roberto Sassu <rsassu@suse.de>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

import os
import sys
import struct
import gevent
import getopt
from gevent import monkey

monkey.patch_all()

import httplib


default_repos_url = [
'http://download.opensuse.org/update/13.2/',
'http://download.opensuse.org/update/13.2-non-oss/',
'http://download.opensuse.org/distribution/13.2/repo/oss/suse/',
'http://download.opensuse.org/distribution/13.2/repo/non-oss/suse/',
]

digests = []

HTTP_GET_MAX_ATTEMPTS = 3


def init_connections(repos, repo_urls):
    for repo_url in repo_urls:
        server = repo_url.split('/')[2:3][0]
        if server not in repos:
            repos[server] = [httplib.HTTPConnection(server)]

        repos[server].append('/'.join(repo_url.split('/')[3:]))


def fetch_data(repos, arch, pkg_filename, url_offset, size, mirror_distro_root):
    new_repo_urls = []

    for server in repos:
        for relative_path in repos[server][1:]:
            attempts = 0
            while attempts < HTTP_GET_MAX_ATTEMPTS:
                try:
                    repos[server][0].request("GET", '/%s/%s/%s' % (relative_path, arch, pkg_filename),
                                            headers={'Range': 'bytes=%s-%s' % (url_offset, url_offset + size),
                                                    'Connection': 'keep-alive'})
                    resp = repos[server][0].getresponse()
                    data = resp.read()
                    break
                except Exception as e:
                    repos[server][0].close()
                    repos[server][0] = httplib.HTTPConnection(server)
                    attempts += 1
                    continue

            if resp.status == 206:
                return data
            elif resp.status == 302:
                repos[server].remove(relative_path)
                if mirror_distro_root is None:
                    redirect_url = resp.getheader('Location')
                    mirror_distro_root = redirect_url[:redirect_url.index(relative_path)]

                new_repo_url = mirror_distro_root + relative_path
                #print 'Server: %s, relative path: %s, redirect to: %s' % (server, relative_path, new_repo_url)
                new_repo_urls.append(new_repo_url)

    if len(new_repo_urls) > 0:
        init_connections(repos, new_repo_urls)
        return fetch_data(repos, arch, pkg_filename, url_offset, size, mirror_distro_root)

    return ''


def get_next_header_offset(num_header_entries, header_data_size):
    next_header_offset = 16 + 16 * num_header_entries + header_data_size
    next_header_offset += next_header_offset % 8
    return next_header_offset


def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def main(packages, repo_urls, mirror_distro_root):
    repos = {}
    total_packages = len(packages)
    count = 1

    init_connections(repos, repo_urls)

    for pkg in packages:
        #print 'Processing (%d/%d): %s' % (count, total_packages, pkg)

        pkg_arch = pkg.split('.')[-1]
        rpm_str = fetch_data(repos, pkg_arch, '%s.rpm' % pkg, 96, 6000, mirror_distro_root)
        if len(rpm_str) == 0:
            print 'Error: %s - signature header' % pkg
            count += 1
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
            count += 1
            continue

        digests_data_offset = num_header_entries * 16 + file_digest_entry[2]
        digests_data_length = file_digest_entry[3] * 33
        if len(rpm_str) <  digests_data_offset + digests_data_length:
            rpm_str = fetch_data(repos, pkg_arch, '%s.rpm' % pkg, 96 + offset + digests_data_offset, digests_data_length, mirror_distro_root)
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


def usage():
    print 'Syntax: %s -i <ima measurements> -p <packages> -r <repositories> -m <mirror distribution root>' % sys.argv[0]


if __name__ == '__main__':
    ima_measurements_path = None
    packages_path = None
    repo_urls_path = None
    mirror_distro_root = None
    threads = 1

    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:p:r:t:m:")
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage()
            sys.exit()
        elif opt in ('-i', '--ima-measurements'):
            ima_measurements_path = arg
        elif opt in ('-p', '--packages'):
            packages_path = arg
        elif opt in ('-r', '--repositories'):
            repo_urls_path = arg
        elif opt in ('-t', '--threads'):
            threads = int(arg)
        elif opt in ('-m', '--mirror-distro-root'):
            mirror_distro_root = arg

    repos_url = default_repos_url
    if repo_urls_path is not None:
        repos_url = []
        try:
            fd = open(repo_urls_path, 'r')
            repos_url_str = fd.read()
            for repo_url_str in repos_url_str.split('\n'):
                if len(repo_url_str) > 0:
                    repos_url.append(repo_url_str)
        except:
            pass

    packages = []
    if packages_path is not None:
        try:
            fd = open(packages_path, 'r')
            packages_str = fd.read()
            for pkg in packages_str.split('\n'):
                if len(pkg) > 0:
                    packages.append(pkg)
        except:
            pass

    # create a database of known digest values
    jobs = [gevent.spawn(main, packages_chunk, repos_url, mirror_distro_root) \
            for packages_chunk in list(chunks(packages, len(packages) / threads))]
    gevent.joinall(jobs)

    if ima_measurements_path is None:
        sys.exit(0)

    # check the IMA file list and display the lines with digests not recognized
    fd = open(ima_measurements_path, 'r')
    report = fd.read()
    fd.close()
    for line in report.split('\n')[:-1]:
        if line.split()[3][4:] not in digests:
            print line
