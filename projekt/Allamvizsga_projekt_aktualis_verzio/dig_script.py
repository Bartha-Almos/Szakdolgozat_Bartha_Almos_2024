import subprocess
import re
import time

def run_dig_command():
    try:
        result = subprocess.run(['dig', '8.8.8.8', '-t', 'A', 'google.com', '+stats'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        # Extract the query time using regex
        match = re.search(r'Query time: (\d+) msec', output)
        if match:
            return int(match.group(1))
        else:
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def main():
    total_time = 0
    successful_queries = 0
    num_queries = 100

    for _ in range(num_queries):
        response_time = run_dig_command()
        if response_time is not None:
            total_time += response_time
            successful_queries += 1
        time.sleep(0.1)  # Slight delay to prevent overwhelming the system/network

    if successful_queries > 0:
        average_time = total_time / successful_queries
        print(f"Average response time over {successful_queries} queries: {average_time:.2f} ms")
    else:
        print("No successful queries were made.")

if __name__ == "__main__":
    main()
