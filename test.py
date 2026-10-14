import os
print("Test process started.")
print("PID:", os.getpid())
while True:
    sum(i * i for i in range(10000))

