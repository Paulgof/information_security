import argparse
import math

from verbose_lib import VerbosePrint


def get_public_key_components(public_key, public_key_path):
    if public_key:
        return public_key

    if not public_key_path:
        public_key_path = 'public.key'

    with open(public_key_path, 'r') as public_key_file:
        return map(int, public_key_file.readlines()[0].strip().split())


def main(input_file, output_file=None, public_key=None, public_key_path=None, verbose=False):
    verbose_print = VerbosePrint(verbose)
    e, n = get_public_key_components(public_key, public_key_path)
    verbose_print(f'Публичный ключ: ({e}, {n})')
    m = int(math.log2(n)) // 8 + 1
    verbose_print(f'm = {m}')
    encrypted_blocks = []
    with open(input_file, 'rb') as input_file_bytes:
        byte = input_file_bytes.read(m)
        while byte != b'':
            block_integer = int.from_bytes(byte, byteorder='big')
            verbose_print('#', byte, bin(block_integer), block_integer, end='\t----->\t', sep='\t')
            encrypted_block = (block_integer ** e) % n
            verbose_print(
                encrypted_block.to_bytes(
                    m,
                    byteorder='big'
                ),
                bin(encrypted_block),
                encrypted_block,
                sep='\t'
            )
            encrypted_blocks.append(encrypted_block)

            byte = input_file_bytes.read(m)

    if not output_file:
        output_file = f'encrypted_{input_file}'

    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(b''.join(map(lambda x: x.to_bytes(m, byteorder='big'), encrypted_blocks)))


if __name__ == '__main__':
    command_line_parser = argparse.ArgumentParser(description='Скрипт шифрования файла при помощи RSA')
    command_line_parser.add_argument('-v', '--verbose', help='Вывод процесса в консоль', action='store_true')
    command_line_parser.add_argument('input_file', type=str, help='Путь до файла, который нужно зашифровать')
    command_line_parser.add_argument('-o', '--output_file', type=str, help='Имя зашифрованного файла')
    public_key_group = command_line_parser.add_mutually_exclusive_group()
    public_key_group.add_argument('-p', '--public_key_path', type=str, help='Путь до файла с публичным ключом')
    public_key_group.add_argument('-k', '--public_key', type=int, nargs=2, help='Публичный ключ (ввод в консоль e и n)')
    options = command_line_parser.parse_args()
    main(
        options.input_file,
        output_file=options.output_file,
        public_key=options.public_key,
        public_key_path=options.public_key_path,
        verbose=options.verbose,
    )
