import os, pprint, pytds, sqlalchemy as sa
from pytds import tds_base

TDS_VER = tds_base.TDS74  # constant 74

conn = pytds.connect(
    server=os.getenv("MSSQL_HOST"),
    port=1433,
    database=os.getenv("MSSQL_DB", "master"),
    user=os.getenv("MSSQL_USER"),
    password=os.getenv("MSSQL_PASSWORD"),
    tds_version=TDS_VER,
)
with conn.cursor() as cur:
    cur.execute("SELECT TOP 5 name, database_id FROM sys.databases")
    pprint.pp(cur.fetchall())


def connect_to_db(db_name: str) -> sa.Engine:
    user, pwd, host = (os.getenv(k)
                       for k in ("MSSQL_USER", "MSSQL_PASSWORD", "MSSQL_HOST"))
    url = f"mssql+pytds://{user}:{pwd}@{host}:1433/{db_name}"
    return sa.create_engine(url,
                            connect_args={"tds_version": TDS_VER},
                            future=True)


engine = connect_to_db(os.getenv("MSSQL_DB", "master"))
with engine.connect() as c:
    print(c.execute(sa.text("SELECT @@version")).scalar_one())
