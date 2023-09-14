import argparse
from utils import encode_jwt, decode_jwt, encode_base64, decode_base64, format_json, encode_url, decode_url, encode_hex, decode_hex, hash_string, generate_uuid

def main():
    parser = argparse.ArgumentParser(description="DevSwissKnife: A Comprehensive Development Toolkit")
    subparsers = parser.add_subparsers(dest="command")

    # JWT subcommands
    jwt_parser = subparsers.add_parser("jwt", help="JWT encoding and decoding")
    jwt_parser.add_argument("--encode", action="store_true", help="Encode JWT")
    jwt_parser.add_argument("--decode", action="store_true", help="Decode JWT")
    jwt_parser.add_argument("--secret", help="Secret key for encoding/decoding JWT", required=True)
    jwt_parser.add_argument("--payload", help="Payload for encoding JWT (JSON string)", required=True)

    # Base64 subcommands
    base64_parser = subparsers.add_parser("base64", help="Base64 encoding and decoding")
    base64_parser.add_argument("--encode", action="store_true", help="Encode base64")
    base64_parser.add_argument("--decode", action="store_true", help="Decode base64")
    base64_parser.add_argument("--input", help="Input string for encoding/decoding base64", required=True)

    # JSON formatting subcommand
    json_parser = subparsers.add_parser("json", help="JSON formatting")
    json_parser.add_argument("--format", action="store_true", help="Format JSON")
    json_parser.add_argument("--input", help="Input JSON string", required=True)

    # URL encoding subcommand
    url_parser = subparsers.add_parser("url", help="URL encoding and decoding")
    url_parser.add_argument("--encode", action="store_true", help="Encode URL")
    url_parser.add_argument("--decode", action="store_true", help="Decode URL")
    url_parser.add_argument("--input", help="Input string for encoding/decoding URL", required=True)

    # Hex encoding subcommand
    hex_parser = subparsers.add_parser("hex", help="Hex encoding and decoding")
    hex_parser.add_argument("--encode", action="store_true", help="Encode hex")
    hex_parser.add_argument("--decode", action="store_true", help="Decode hex")
    hex_parser.add_argument("--input", help="Input string for encoding/decoding hex", required=True)

    # Hashing subcommand
    hash_parser = subparsers.add_parser("hash", help="Hashing")
    hash_parser.add_argument("--alg", help="Hashing algorithm", required=True, choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
    hash_parser.add_argument("--input", help="Input string for hashing", required=True)

    # UUID subcommand
    uuid_parser = subparsers.add_parser("uuid", help="UUID generation")
    uuid_parser.add_argument("--generate", action="store_true", help="Generate UUID")

    # Parse arguments
    args = parser.parse_args()

    # JWT
    if args.command == "jwt":
        if args.encode:
            print(encode_jwt(args.secret, args.payload))
        elif args.decode:
            print(decode_jwt(args.secret, args.payload))
        else:
            print("Missing JWT subcommand")

    # Base64
    elif args.command == "base64":
        if args.encode:
            print(encode_base64(args.input))
        elif args.decode:
            print(decode_base64(args.input))
        else:
            print("Missing Base64 subcommand")

    # JSON
    elif args.command == "json":
        if args.format:
            print(format_json(args.input))
        else:
            print("Missing JSON subcommand")

    # URL
    elif args.command == "url":
        if args.encode:
            print(encode_url(args.input))
        elif args.decode:
            print(decode_url(args.input))
        else:
            print("Missing URL subcommand")

    # Hex
    elif args.command == "hex":
        if args.encode:
            print(encode_hex(args.input))
        elif args.decode:
            print(decode_hex(args.input))
        else:
            print("Missing Hex subcommand")

    # Hash
    elif args.command == "hash":
        print(hash_string(args.input, args.alg))

    # UUID
    elif args.command == "uuid":
        if args.generate:
            print(generate_uuid())
        else:
            print("Missing UUID subcommand")

    else:
        print("Missing command")

if __name__ == "__main__":
    main()