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

log = logging.getLogger()
log.setLevel('DEBUG')
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
log.addHandler(handler)

from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

KEYSPACE = "key_space0"


def main():
    cluster = Cluster(['127.0.0.1'])
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

    query = SimpleStatement("""
        INSERT INTO test_table (thekey, col1, col2)
        VALUES (%(key)s, %(a)s, %(b)s)
        """)

    prepared = session.prepare("""
        INSERT INTO test_table (thekey, col1, col2)
        VALUES (?, ?, ?)
        """)

    for i in range(3):
        log.info("inserting row %d" % i)
        session.execute(query, dict(key="key%d" % i, a='a', b='b'))
        session.execute(prepared, ("key%d" % i, 'a', 'a'))

    future = session.execute_async("SELECT * FROM test_table")
    log.info("key\tcol1\tcol2")
    log.info("---\t----\t----")

    try:
        rows = future.result()
    except Exception:
        log.exception("Error reading rows:")
        return

    for row in rows:
        log.info('\t'.join(row))

    # session.execute("DROP KEYSPACE " + KEYSPACE)

if __name__ == "__main__":
    main()
