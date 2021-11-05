import argparse
import math

from verbose_lib import VerbosePrint


ENCRYPT_MODE = 'ENCRYPT_MODE'
DECRYPT_MODE = 'DECRYPT_MODE'


def get_key_components(key, key_path, is_encrypt_mode):
    """Получение пары (e, n) в режиме шифрования или (d, n) в режиме дешифрования"""
    if key:
        return key

    if not key_path:
        key_path = 'public.key' if is_encrypt_mode else 'private.key'

    with open(key_path, 'r') as public_key_file:
        return map(int, public_key_file.readlines()[0].strip().split())


def bytes_to_binary_view(bytes_message):
    return ''.join(map(lambda x: '{:0>8b}'.format(x), bytes_message))


def main(input_file: str, mode=ENCRYPT_MODE, output_file=None, key=None, key_path=None, verbose=False):
    is_encrypt_mode = mode == ENCRYPT_MODE
    verbose_print = VerbosePrint(verbose)

    key_var, key_base = get_key_components(key, key_path, is_encrypt_mode)
    verbose_print(
        f'Публичный ключ: ({key_var}, {key_base})' if is_encrypt_mode else f'Приватный ключ: ({key_var}, {key_base})',
    )
    bytes_window = int(math.log2(key_base)) // 8
    verbose_print(f'Длина блока шифрования = {bytes_window} (байт)')

    crypted_blocks = []
    with open(input_file, 'rb') as input_file_bytes:
        byte = input_file_bytes.read(1)
        while byte:
            block_integer = int.from_bytes(byte, byteorder='little')
            verbose_print('#', byte, bin(block_integer), block_integer, end='\t----->\t', sep='\t')
            crypted_block = (block_integer ** key_var) % key_base
            verbose_print(
                crypted_block.to_bytes(
                    1,
                    byteorder='little'
                ),
                bin(crypted_block),
                crypted_block,
                sep='\t'
            )
            crypted_blocks.append(crypted_block)

            byte = input_file_bytes.read(1)

    if not output_file:
        if not is_encrypt_mode and 'encrypted' in input_file:
            output_file = input_file.replace('encrypted', 'decrypted')
        else:
            output_file = f'encrypted_{input_file}' if is_encrypt_mode else f'decrypted_{input_file}'

    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(b''.join(map(lambda x: x.to_bytes(bytes_window, byteorder='little'), crypted_blocks)))


if __name__ == '__main__':
    command_line_parser = argparse.ArgumentParser(description='Скрипт шифрования/дешифрования файла при помощи RSA')
    command_line_parser.add_argument(
        '-d',
        '--decrypt',
        help='Режим дешифрования файла (по умолчанию файл шифруется)',
        action='store_true',
    )
    command_line_parser.add_argument('input_file', type=str, help='Путь до файла, который нужно шифровать/дешифровать')
    command_line_parser.add_argument('-o', '--output_file', type=str, help='Имя преобразованного файла')
    key_group = command_line_parser.add_mutually_exclusive_group()
    key_group.add_argument('-p', '--key_path', type=str, help='Путь до файла с приватным ключом')
    key_group.add_argument(
        '-k',
        '--key',
        type=int,
        nargs=2,
        help='Ключ (ввод в консоль двух чисел)',
    )
    command_line_parser.add_argument('-v', '--verbose', help='Вывод процесса в консоль', action='store_true')
    arguments = command_line_parser.parse_args()
    main(
        arguments.input_file,
        mode=DECRYPT_MODE if arguments.decrypt else ENCRYPT_MODE,
        output_file=arguments.output_file,
        key=arguments.key,
        key_path=arguments.key_path,
        verbose=arguments.verbose,
    )
