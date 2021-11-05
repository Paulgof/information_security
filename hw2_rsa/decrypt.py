import argparse
import math

from verbose_lib import VerbosePrint


def get_private_key_components(private_key, private_key_path):
    if private_key:
        return private_key

    if not private_key_path:
        private_key_path = 'private.key'

    with open(private_key_path, 'r') as public_key_file:
        return map(int, public_key_file.readlines()[0].strip().split())


def main(input_file: str, output_file=None, private_key=None, private_key_path=None, verbose=False):
    verbose_print = VerbosePrint(verbose)
    d, n = get_private_key_components(private_key, private_key_path)
    verbose_print(f'Приватный ключ: ({d}, {n})')
    m = int(math.log2(n)) // 8 + 1
    verbose_print(f'm = {m}')
    decrypted_blocks = []
    with open(input_file, 'rb') as input_file_bytes:
        byte = input_file_bytes.read(m)
        while byte != b'':
            block_integer = int.from_bytes(byte, byteorder='big')
            verbose_print('#', byte, bin(block_integer), block_integer, end='\t----->\t', sep='\t')
            decrypted_block = (block_integer ** d) % n
            verbose_print(
                decrypted_block.to_bytes(
                    m,
                    byteorder='big'
                ),
                bin(decrypted_block),
                decrypted_block,
                sep='\t'
            )
            decrypted_blocks.append(decrypted_block)

            byte = input_file_bytes.read(m)

    if not output_file:
        if 'encrypted' in input_file:
            output_file = input_file.replace('encrypted', 'decrypted')
        else:
            output_file = f'decrypted_{input_file}'

    with open(output_file, 'wb') as decrypted_file:
        decrypted_file.write(b''.join(map(lambda x: x.to_bytes(m, byteorder='big'), decrypted_blocks)))


if __name__ == '__main__':
    command_line_parser = argparse.ArgumentParser(description='Скрипт дешифрования файла при помощи RSA')
    command_line_parser.add_argument('-v', '--verbose', help='Вывод процесса в консоль', action='store_true')
    command_line_parser.add_argument('input_file', type=str, help='Путь до файла, который нужно дешифровать')
    command_line_parser.add_argument('-o', '--output_file', type=str, help='Имя дешифрованного файла')
    private_key_group = command_line_parser.add_mutually_exclusive_group()
    private_key_group.add_argument('-p', '--private_key_path', type=str, help='Путь до файла с приватным ключом')
    private_key_group.add_argument(
        '-k',
        '--private_key',
        type=int,
        nargs=2,
        help='Приватный ключ (ввод в консоль d и n)',
    )
    options = command_line_parser.parse_args()
    main(
        options.input_file,
        output_file=options.output_file,
        private_key=options.private_key,
        private_key_path=options.private_key_path,
        verbose=options.verbose,
    )
