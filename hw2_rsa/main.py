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
    verbose_print(f'{"Шифрование" if is_encrypt_mode else "Дешифрование"} файла {input_file}')

    key_var, key_base = get_key_components(key, key_path, is_encrypt_mode)
    verbose_print(
        f'Публичный ключ: ({key_var}, {key_base})' if is_encrypt_mode else f'Приватный ключ: ({key_var}, {key_base})',
    )
    bits_step = int(math.log2(key_base))
    # bits_length = 2 ** bits_step
    verbose_print(f'Длина блока шифрования = {bits_step} бит(а)')
    with open(input_file, 'rb') as input_file_bytes:
        bytes_file_data = b''.join(input_file_bytes.readlines())
        binary_view = bytes_to_binary_view(bytes_file_data)
        verbose_print(f'b\tДвоичное представление входного файла:\n{binary_view}\n')

    does_next_have_extra_bit = False
    extra_flag = '1' * bits_step  # файловый флаг, что следующий блок на 1 бит больше стандартного
    margin = 0  # количество смещений из-за экстра блоков
    crypted_windows = []
    verbose_print(f'{"№":<4}{"bin":^16}{"int":^16}{"cr_bin":^16}{"cr_int":^16}')
    for window_number, window_start in enumerate(range(0, len(binary_view), bits_step), start=1):
        extra_bit = 0
        if not is_encrypt_mode and does_next_have_extra_bit:
            extra_bit = 1

        window = binary_view[window_start + margin:window_start + bits_step + margin + extra_bit]
        if not is_encrypt_mode and window == extra_flag:
            verbose_print('\tEXTRA_FLAG: пропуск блока, длина следующего будет на 1 больше стандартного.')
            does_next_have_extra_bit = True
            continue

        if not is_encrypt_mode and does_next_have_extra_bit:
            does_next_have_extra_bit = False
            margin += 1

        if window == '':
            break

        window_int = int(window, base=2)
        crypted_window_int = (window_int ** key_var) % key_base
        crypted_window = '{{:0>{}b}}'.format(bits_step).format(crypted_window_int)
        if is_encrypt_mode and len(crypted_window) > bits_step:
            crypted_windows.append(extra_flag)
            verbose_print('\t+ EXTRA_FLAG for next block')

        verbose_print(f'{window_number:<4}{window:^16}{window_int:^16}{crypted_window:^16}{crypted_window_int:^16}')
        crypted_windows.append(crypted_window)

    crypted_binary_view = ''.join(crypted_windows)
    verbose_print(f'\nb\tДвоичное представление выходного файла:\n{crypted_binary_view}\n')
    crypted_blocks = []
    for crypted_block_start in range(0, len(crypted_binary_view), 8):
        window = crypted_binary_view[crypted_block_start:crypted_block_start + 8]
        window_int = int(window, base=2)
        crypted_blocks.append(window_int.to_bytes(1, byteorder='big'))

    if not output_file:
        if not is_encrypt_mode and 'encrypted' in input_file:
            output_file = input_file.replace('encrypted', 'decrypted')
        else:
            output_file = f'encrypted_{input_file}' if is_encrypt_mode else f'decrypted_{input_file}'

    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(b''.join(crypted_blocks))


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
