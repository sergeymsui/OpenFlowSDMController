# input_console.py

from blessed import Terminal

term = Terminal()

history = []
input_buffer = ""


def main():
    global input_buffer

    with term.fullscreen(), term.cbreak(), term.hidden_cursor():
        print(term.clear())
        while True:
            # Отрисовка истории
            print(term.move(0, 0) + term.clear())
            max_lines = term.height - 2
            visible_history = history[-max_lines:]
            for i, line in enumerate(visible_history):
                print(term.move(i, 0) + line)

            # Отрисовка строки ввода
            print(
                term.move(term.height - 1, 0) + term.clear_eol + f"> {input_buffer}",
                end="",
                flush=True,
            )

            key = term.inkey(timeout=0.1)

            if not key:
                continue

            if key.name == "KEY_ENTER":
                if input_buffer.strip().lower() in ("exit", "quit"):
                    break
                history.append(input_buffer)
                input_buffer = ""
            elif key.name == "KEY_BACKSPACE":
                input_buffer = input_buffer[:-1]
            elif not key.is_sequence:
                input_buffer += key


if __name__ == "__main__":
    main()
