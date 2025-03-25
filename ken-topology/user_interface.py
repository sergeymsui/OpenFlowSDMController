from blessed import Terminal
import threading
import sys
import time


class UserInterface:
    def __init__(self, controller):
        self.term = Terminal()
        self.controller = controller
        self.running = False
        self.log_lines = []  # Строки логов (stdout)
        self.max_logs = 20  # Ограничим вывод до последних 20 строк

    def start(self):
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

        # Перехватываем stdout
        sys.stdout = self

    def write(self, data):
        """Перехватываем print и сохраняем логи"""
        if data.strip():
            self.log_lines.append(data.strip())
            if len(self.log_lines) > self.max_logs:
                self.log_lines = self.log_lines[-self.max_logs :]

    def flush(self):
        pass  # нужен для совместимости с sys.stdout

    def run(self):
        with self.term.fullscreen(), self.term.cbreak(), self.term.hidden_cursor():
            while self.running:
                self.draw_output()
                self.handle_input()

    def draw_output(self):
        print(self.term.home + self.term.clear)

        # Верхняя часть — вывод логов
        print(self.term.bold("📡 SDN Controller Output (logs):"))
        for i, line in enumerate(self.log_lines[-self.term.height + 5 :]):
            print(self.term.move(i + 1, 0) + self.term.white(line))

        # Нижняя часть — команды
        bottom = self.term.height - 3
        print(self.term.move(bottom, 0) + self.term.bold("💻 Command interface:"))
        print(self.term.move(bottom + 1, 0) + "1 - Show topology | q - Quit")

    def handle_input(self):
        key = self.term.inkey(timeout=1)
        if not key:
            return

        if key == "1":
            self.controller.draw_topology()
            self.log_lines.append("[UI] Topology graph updated and saved.")
        elif key == "q":
            self.running = False
            self.log_lines.append("[UI] Exiting interface...")
            sys.stdout = sys.__stdout__  # Восстановим stdout
