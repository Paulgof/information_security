import argparse
import random

from typing import Dict, Tuple


class VerbosePrint:
    """Класс для вывода сообщений в консоль в режиме verbose"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def __call__(self, *args, **kwargs):
        self.print(*args, **kwargs)

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)


def generate_primary_numbers(n_max=100):
    primary_numbers = []
    for number in range(2, n_max + 1):
        if not any(map(lambda x: number % x == 0, primary_numbers)):
            primary_numbers.append(number)

    return primary_numbers


def find_border_index(euler_value, primary_numbers):
    index = 0
    while index < len(primary_numbers) and primary_numbers[index] < euler_value:
        index += 1

    return index - 1


def find_d(e, euler_value):
    for d in range(2, euler_value):
        if (d * e) % euler_value == 1:
            return d

    raise ValueError(f'Обратное к e={e} число d не найдено!')


def main(seed=None, verbose=False) -> Dict[str, Tuple[int, int]]:
    verbose_print = VerbosePrint(verbose)
    verbose_print(
        'Генератор RSA ключей',
        'режим вывода процесса в консоль',
        f'Случайное зерно = {seed}' if seed else 'Случайное зерно не задано, использование времени в качестве зерна',
        sep='\n',
        end='\n----------\n\n'
    )
    random.seed(seed)
    verbose_print('Начало генерации множества простых чисел')
    primary_numbers = generate_primary_numbers()
    verbose_print('Количество простых чисел:', len(primary_numbers))
    p, q = (primary_numbers.pop(random.randint(0, len(primary_numbers))) for _ in range(2))
    verbose_print(f'Полученные значения p = {p}, q = {q}')
    n: int = p * q
    euler_function_value = (p - 1) * (q - 1)
    verbose_print(f'Подсчитанные значения n = {n}, Ф(n) = {euler_function_value}')
    e_prim = primary_numbers[:find_border_index(euler_function_value, primary_numbers)]
    e_prim = list(filter(lambda x: euler_function_value % x != 0, e_prim))
    e: int = random.choice(e_prim)
    verbose_print(f'Полученное значение e = {e}')
    d: int = find_d(e, euler_function_value)
    verbose_print(f'Найденное значение d = {d}')
    verbose_print(f'\n--- Публичный ключ: ({e}, {n}) ---')
    verbose_print(f'\n--- Приватный ключ: ({d}, {n}) ---', end='\n\n')

    verbose_print(f'Запись публичного ключа в файл public.key')
    with open('public.key', 'w') as public_key:
        public_key.write(f'{e} {n}')

    verbose_print(f'Запись приватного ключа в файл private.key')
    with open('private.key', 'w') as private_key:
        private_key.write(f'{d} {n}')

    return {'public_key': (e, n), 'private_key': (d, n)}


if __name__ == '__main__':
    command_line_parser = argparse.ArgumentParser(description='RSA генератор открытого и закрытого ключей')
    command_line_parser.add_argument('-s', '--seed', type=int, help='Случайное зерно (random seed)')
    command_line_parser.add_argument('-v', '--verbose', help='Вывод процесса в консоль', action='store_true')
    options = command_line_parser.parse_args()
    main(options.seed, options.verbose)
