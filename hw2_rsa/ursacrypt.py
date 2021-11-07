import argparse
import math
import time

ENCRYPT_MODE = 'ENCRYPT_MODE'
DECRYPT_MODE = 'DECRYPT_MODE'


class VerbosePrint:
    """Класс для вывода сообщений в консоль в режиме verbose"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def __call__(self, *args, **kwargs):
        self.print(*args, **kwargs)

    def print(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)


def get_key_components(key, key_path, is_encrypt_mode):
    """Получение пары (e, n) в режиме шифрования или (d, n) в режиме дешифрования"""
    if key:
        return key

    if not key_path:
        key_path = 'public.key' if is_encrypt_mode else 'private.key'

    with open(key_path, 'r') as public_key_file:
        return map(int, public_key_file.readlines()[0].strip().split())


def bytes_to_binary_view(bytes_message):
    """Функция для преобразования bytes-строки в бинарное представление"""
    return ''.join(map(lambda x: '{:0>8b}'.format(x), bytes_message))


def crypt(input_file: str, mode=ENCRYPT_MODE, output_file=None, key=None, key_path=None, verbose=False):
    """Главный метод модуля"""
    is_encrypt_mode = mode == ENCRYPT_MODE
    is_decrypt_mode = mode == DECRYPT_MODE
    verbose_print = VerbosePrint(verbose)
    verbose_print(f'{"Шифрование" if is_encrypt_mode else "Дешифрование"} файла {input_file}')
    verbose_print('режим вывода процесса в консоль')

    # Извлечение значений ключа
    key_var, key_base = get_key_components(key, key_path, is_encrypt_mode)
    verbose_print(f'{"Публичный ключ" if is_encrypt_mode else "Приватный ключ"}: ({key_var}, {key_base})')

    # Вычисление длины блока шифрования (для изначальных данных) и блока кратности (для зашифрованных данных)
    origin_bits_step = int(math.log2(key_base))
    unified_bits_step = origin_bits_step + 8 - (origin_bits_step % 8)
    mode_step = origin_bits_step if is_encrypt_mode else unified_bits_step
    origin_bits_template = '{{:0>{}b}}'.format(origin_bits_step)
    unified_bits_template = '{{:0>{}b}}'.format(unified_bits_step)
    mode_template = unified_bits_template if is_encrypt_mode else origin_bits_template
    verbose_print(f'Длина блока шифрования = {origin_bits_step} bits, длина блока кратности = {unified_bits_step} bits')

    # Чтение входного файла и представление его в двоичном виде
    binary_view = ''
    with open(input_file, 'rb') as input_file_bytes:
        bytes_file_data = b''.join(input_file_bytes.readlines())
        if not bytes_file_data:
            raise ValueError('No data to encrypt/decrypt')

        binary_view = bytes_to_binary_view(bytes_file_data)

    last_block_skip = 0
    if is_encrypt_mode:
        last_block_length_info = len(binary_view) % origin_bits_step
    else:
        binary_view, last_block_length_info = binary_view[:-unified_bits_step], binary_view[-unified_bits_step:]
        last_block_length_info = int(last_block_length_info, base=2)
        last_block_skip = unified_bits_step
        verbose_print(f'Чтение длины последнего блока: {last_block_length_info} bits')

    if verbose:
        time.sleep(3)

    crypted_windows = []
    verbose_print(f'{"№":<4}{"bin":^32}{"int":^8}{"cr_bin":^32}{"cr_int":^8}')
    for window_number, window_start in enumerate(range(0, len(binary_view) - last_block_skip, mode_step), start=1):
        window = binary_view[window_start:window_start + mode_step]
        if window == '':  # конец файла
            break

        window_int = int(window, base=2)
        crypted_window_int = (window_int ** key_var) % key_base
        crypted_window = mode_template.format(crypted_window_int)
        verbose_print(f'{window_number:<4}{window:^32}{window_int:^8}{crypted_window:^32}{crypted_window_int:^8}')
        crypted_windows.append(crypted_window)

    if is_decrypt_mode:
        last_window = binary_view[-unified_bits_step:]
        last_window_int = int(last_window, base=2)
        crypted_last_window_int = (last_window_int ** key_var) % key_base
        crypted_last_window = '{{:0>{}b}}'.format(last_block_length_info).format(crypted_last_window_int)
        verbose_print(f'{"L":<4}{last_window:^32}{last_window_int:^8}{crypted_last_window:^32}'
                      f'{crypted_last_window_int:^8}')
        crypted_windows.append(crypted_last_window)

    crypted_binary_view = ''.join(crypted_windows)
    crypted_blocks = []
    for crypted_block_start in range(0, len(crypted_binary_view), 8):
        window = crypted_binary_view[crypted_block_start:crypted_block_start + 8]
        window_int = int(window, base=2)
        crypted_blocks.append(window_int.to_bytes(1, byteorder='big'))

    if is_encrypt_mode:
        verbose_print(f'\nЗапись длины последнего блока: {last_block_length_info} bits')
        crypted_blocks.append(last_block_length_info.to_bytes(unified_bits_step // 8, byteorder='big'))

    if not output_file:
        if is_decrypt_mode and '.enc' in input_file:
            output_file = input_file.replace('.enc', '', 1)
            output_file = f'{output_file[:output_file.rindex(".")]}_decrypted{output_file[output_file.rindex("."):]}'
        else:
            output_file = f'{input_file}.enc' if is_encrypt_mode else f'{input_file}.dec'

    with open(output_file, 'wb') as decrypted_file:
        verbose_print(f'Запись {"зашифрованных" if is_encrypt_mode else "дешифрованных"} данных в файл {output_file}')
        decrypted_file.write(b''.join(crypted_blocks))


if __name__ == '__main__':
    command_line_parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Скрипт шифрования/дешифрования файла при помощи алгоритма uRSA ([u]nified-blocks RSA)',
        epilog='''
    По умолчанию используется режим шифрования файла. Для дешифрования укажите опцию -d (или --decrypt).

    Аргумент пути входного файла input_file обязателен. Если путь до файла содержит пробелы, его следует обернуть в 
    кавычки.

    Опция пути выходного файла -o (--output_file) необязательна. Если она не указана, то выходным файлом будет 
    encrypted_<ИМЯ ВХОДНОГО ФАЙЛА> или decrypted_<ИМЯ ВХОДНОГО ФАЙЛА> (в зависимости от режима).

    Если не указаны опции ключа -k (--key) или -p (--key_path), тогда:
        1) в режиме шифрования публичный ключ берётся из файла public.key в текущей директории
        2) в режиме дешифрования приватный ключ берётся из файла private.key в текущей директории
    Если не указаны опции ключа и в текущей директории нет нужного файла, возникнет ошибка чтения файла.

    Пример использования скрипта для шифрования файла:
    python rsacrypt.py test.txt -o enc_test.txt -p pub.k -v

    Пример использования скрипта для дешифрования файла:
    python rsacrypt.py enc_test.txt -dv -k 749 893
        '''
    )
    command_line_parser.add_argument(
        '-d',
        '--decrypt',
        help='Режим дешифрования файла (по умолчанию файл шифруется)',
        action='store_true',
    )
    command_line_parser.add_argument('input_file', type=str, help='Путь до файла, который нужно шифровать/дешифровать')
    command_line_parser.add_argument('-o', '--output_file', type=str, help='Имя преобразованного файла')
    key_group = command_line_parser.add_mutually_exclusive_group()
    key_group.add_argument('-p', '--key_path', type=str, help='Путь до файла с ключом')
    key_group.add_argument(
        '-k',
        '--key',
        type=int,
        nargs=2,
        help='Ключ (ввод в консоль двух чисел)',
    )
    command_line_parser.add_argument('-v', '--verbose', help='Вывод процесса в консоль', action='store_true')
    arguments = command_line_parser.parse_args()
    crypt(
        arguments.input_file,
        mode=DECRYPT_MODE if arguments.decrypt else ENCRYPT_MODE,
        output_file=arguments.output_file,
        key=arguments.key,
        key_path=arguments.key_path,
        verbose=arguments.verbose,
    )
