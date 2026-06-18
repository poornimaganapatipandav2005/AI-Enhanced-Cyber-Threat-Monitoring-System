from db import get_engine, DB_PATH
import pandas as pd

ENGINE = get_engine()
print('DB file:', DB_PATH)

tables = ['logs','users','blocked_ips','intruders','login_history']
for t in tables:
    try:
        df = pd.read_sql_query(f"SELECT * FROM {t}", ENGINE)
        print(f"{t}: {len(df)} rows")
    except Exception as e:
        print(f"{t}: ERROR - {e}")

# print sample rows for logs and users
for t in ['logs','users']:
    try:
        df = pd.read_sql_query(f"SELECT * FROM {t} LIMIT 5", ENGINE)
        print('\nSample from', t)
        print(df.to_string(index=False))
    except Exception:
        pass
