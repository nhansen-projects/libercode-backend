#!/usr/bin/env python3

import subprocess
import sys

def run_db_query(query):
    # Run a PostgreSQL query using Docker
    try:
        cmd = [
            'docker', 'exec', 'libercode-backend-db-1', 
            'psql', '-U', 'admin', '-d', 'notesDB', '-c', query
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("Query successful:")
            print(result.stdout)
        else:
            print(f"Query failed with return code {result.returncode}:")
            print(result.stderr)
            
    except Exception as e:
        print(f"Error running query: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python db_query_simple.py "SELECT * FROM table;"')
        sys.exit(1)
    
    query = sys.argv[1]
    print(f"Running query: {query}")
    print("=" * 50)
    run_db_query(query)