#!/usr/bin/env python

# Copyright 2013-2017 DataStax, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import sys

log = logging.getLogger()
log.setLevel('DEBUG')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
log.addHandler(handler)

from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

KEYSPACE = "key_space1"


def main():
    if len(sys.argv) != 4:
        print("usage: python example_core.py add/del num_operations name")
        exit(1)
    num_operations = int(sys.argv[2])
    key_name = sys.argv[3]
    cluster = Cluster(['10.0.0.2'])
    session = cluster.connect()

    log.info("creating key space...")
    session.execute("""
        CREATE KEYSPACE IF NOT EXISTS %s
        WITH replication = { 'class': 'SimpleStrategy', 'replication_factor': '1' }
        """ % KEYSPACE)

    log.info("setting keyspace...")
    session.set_keyspace(KEYSPACE)

    log.info("creating table...")
    session.execute("CREATE TABLE IF NOT EXISTS test_table (thekey text PRIMARY KEY, col1 text, col2 text);")

    # query = SimpleStatement("""
    #     INSERT INTO test_table (thekey, col1, col2)
    #     VALUES (%(key)s, %(a)s, %(b)s)
    #     """)

    # prepared = session.prepare("""
    #     INSERT INTO test_table (thekey, col1, col2)
    #     VALUES (?, ?, ?)
    #     """)
    # session.execute("insert into key_space1.test_table (thekey, col1, col2) values ('keya', 'aa', 'bb')")

    # session.execute("DELETE FROM test_table where thekey = 'keya';")
    # session.execute("insert into key_space1.test_table (thekey, col1, col2) values ('keya', 'cc', 'dd')")
    # for i in range(num_operations):
    #     log.info("inserting row %d" % i)
    #     session.execute(prepared, ("key%d" % i, 'e', 'e'))
    # session.execute("insert into key_space1.test_table (thekey, col1, col2) values ('keyb', 'ee', 'ff')")
    if sys.argv[1] == "add":
        for i in range(num_operations):
            query = "insert into key_space1.test_table (thekey, col1, col2) values ('key_%s%s', 'aa', 'bb')" % (key_name, i)
            session.execute(query)
    elif sys.argv[1] == "del":
        for i in range(num_operations):
            query = "delete from key_space1.test_table where thekey = 'key_%s%s'" % (key_name, i)
            session.execute(query)
    else:
        print("opcode %s is wrong." % sys.argv[1])

    rows = session.execute("SELECT * FROM test_table")
    log.info("key\tcol1\tcol2")
    log.info("---\t----\t----")

    for row in rows:
        log.info('\t'.join(row))

    # session.execute("DROP KEYSPACE " + KEYSPACE)

if __name__ == "__main__":
    main()
