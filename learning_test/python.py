import sys
from collections import OrderedDict


def test_first_non_repeating(s: str) -> str:
    # LinkedHashMap preserves the insertion order of characters
    char_count = OrderedDict()

    for char in s:
        char_count[char] = char_count.get(char, 0) + 1

    for char, count in char_count.items():
        if count == 1:
            return char

    return "_"


def main() -> None:
    if len(sys.argv) > 1:
        inputs = sys.argv[1:]
    else:
        user_input = input("Enter a string: ").strip()
        if not user_input:
            print("No input provided.")
            return
        inputs = [user_input]

    for s in inputs:
        result = test_first_non_repeating(s)
        print(f"{s} -> {result}")


if __name__ == "__main__":
    main()