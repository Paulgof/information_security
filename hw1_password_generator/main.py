import random, string
print(''.join(random.choice(list(map(str, range(10)))) for _ in range(6)))
print(''.join(random.choice(string.digits) for _ in range(6)))
print(''.join(str(random.choice(range(10))) for _ in range(6)))
[print(random.choice(range(10)), end='') for _ in range(6)]
print()
print(random.randint(100000, 999999))
