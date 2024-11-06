import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QComboBox
import S_AES_algorithm

class MyWindow(QWidget):
    def __init__(self):
        super().__init__()

        # 设置窗口标题和窗口大小
        self.setWindowTitle("S-AES加密算法")
        self.setGeometry(100, 100, 400, 300)  # 调整窗口大小为400x300

        # 创建标签和输入框
        self.label_input = QLabel('输入明文:')
        self.input_field = QLineEdit(self)

        self.label_key = QLabel('输入密钥:')
        self.key_field = QLineEdit(self)

        self.encrypt_button = QPushButton('加密')

        # 添加模式选择框
        self.label_mode = QLabel('选择模式:')
        self.mode_selector = QComboBox(self)
        self.mode_selector.addItem("16bit")
        self.mode_selector.addItem("ASCII字符串")

        self.label_result = QLabel('密文为:')
        self.result_field = QLineEdit(self)
        self.result_field.setReadOnly(True)  # 结果框设置为只读

        # 设置布局
        layout = QVBoxLayout()
        layout.addWidget(self.label_input)
        layout.addWidget(self.input_field)
        layout.addWidget(self.label_key)
        layout.addWidget(self.key_field)
        layout.addWidget(self.label_mode)
        layout.addWidget(self.mode_selector)  # 添加模式选择器
        layout.addWidget(self.encrypt_button)
        layout.addWidget(self.label_result)
        layout.addWidget(self.result_field)

        # 将布局应用到窗口
        self.setLayout(layout)

        # 绑定按钮点击事件到加密方法
        self.encrypt_button.clicked.connect(self.encrypt)

    def encrypt(self):
        plaintext = self.input_field.text()
        key = self.key_field.text()

        # 获取当前选择的模式
        mode = self.mode_selector.currentText()

        # 如果模式为 "16bit"，检查明文是否为16位的二进制数
        if mode == "16bit":
            if not S_AES_algorithm.S_AES.isright(plaintext, 16):
                self.result_field.setText('明文格式错误（应为16位二进制）')
                return  # 添加返回，停止执行
        # 如果模式为 "ASCII字符串"，检查明文是否为ASCII编码
        elif mode == "ASCII字符串":
            if not S_AES_algorithm.S_AES.is_ASCII_text(plaintext):
                self.result_field.setText('明文格式错误（应为ASCII字符串）')
                return  # 添加返回，停止执行

        # 检查密钥是否为16位的二进制数
        if S_AES_algorithm.S_AES.isright(key, 16):
            test = S_AES_algorithm.S_AES(key)
            result = test.encrypt(plaintext,mode)
            encrypted_text = f"{result}"
            self.result_field.setText(encrypted_text)
        else:
            self.result_field.setText('密钥格式错误')

if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MyWindow()
    window.show()

    sys.exit(app.exec_())