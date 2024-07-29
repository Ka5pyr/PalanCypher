#!/usr/bin/env python3

import argparse
import base64
import hashlib
import sys
import urllib.parse


def arg_parser():
    parser = argparse.ArgumentParser(
        description = 'Encode/Decoder Application'
    )
    options = parser.add_subparsers(dest="option", help="Program Options")

    # Encoding Options
    encoder = options.add_parser('encode', aliases=['-e', '--ENCODE'],
                                  help="Encode Option")

    encode_group = encoder.add_mutually_exclusive_group(required=True)
    encode_group.add_argument('-b', '--BASE64', help='Base64 Algorithm', action='store_true')
    encode_group.add_argument('-u', '--URL', help='URL Algorithm', action='store_true')

    # Decoding Options
    decoder = options.add_parser('decode', aliases=['-d', '--DECODE'],
                                  help="Decode Option")
    
    decode_group = decoder.add_mutually_exclusive_group(required=True)
    decode_group.add_argument('-b', '--BASE64', help='Base64 Algorithm', action='store_true')
    decode_group.add_argument('-u', '--URL', help='URL Algorithm', action='store_true')

    # Hashing Options
    hasher = options.add_parser('hash', aliases=['-h', '--HASH'],
                                  help="Decode Option")

    hash_group = hasher.add_mutually_exclusive_group(required=True)
    hash_group.add_argument('--md5', help='MD5 Algorithm', action='store_true')
    hash_group.add_argument('--sha1', help='SHA1 Algorithm', action='store_true')
    hash_group.add_argument('--sha256', help='SHA256 Algorithm', action='store_true')

    parser.add_argument('-i', '--INPUT', help="Input String", required=True)

    return parser.parse_args()


def main(args):

    if args.option == 'decode':
        input_str = args.INPUT.encode('ascii')
        if args.BASE64:
            print(base64.b64decode(b64_string).decode('ascii')) 
        elif args.URL:
            print(urllib.parse.unquote(input_str))
        else:
            print("Please choose --BASE64 or --URL")
            sys.exit(1)

    elif args.option == 'encode':
        input_str = args.INPUT.encode('ascii')
        # print(input_str)
        print(args)
        if args.BASE64:
            print(base64.b64encode(input_str).decode('ascii'))
        elif args.URL:
            print(urllib.parse.quote(input_str))
        else:
            print("Please choose --BASE64 or --URL")
            sys.exit(1)

    elif args.option == 'hash':
        input_str = args.INPUT.encode('ascii')
        #print(args)

        if args.md5:
            hash_string = hashlib.md5(input_str)
        elif args.sha1:
            hash_string = hashlib.sha1(input_str)
        elif args.sha256:
            hash_string = hashlib.sha256(input_str)
        else:
            print("Please choose between md5, sha1, and sha256")
            sys.exit(1)

        print(hash_string.hexdigest())
    else:
        print("Please choose encode, decode, or hashing")
        sys.exit(1)


if __name__ == "__main__":
    
    args = arg_parser()
    main(args)