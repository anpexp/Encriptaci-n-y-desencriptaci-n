from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QHBoxLayout, QLineEdit, QWidget, QStackedWidget
)
from PyQt5.QtCore import Qt
import sys
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import matplotlib.cm as cm
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QSizePolicy
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QMessageBox
import random
from math import gcd, sqrt
from analisisdebrauer import iniciar_visualizacion
import numpy as np
from sympy import Matrix



class LorenCriptum(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Loren Criptum")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff; font-family: 'Roboto', sans-serif;")

        # Main widget to handle multiple pages
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        # Pages
        self.main_page = self.create_main_page()
        self.encrypt_page = self.create_encrypt_page()
        self.attack_page = self.create_attack_page()

        # Add pages to stack
        self.stack.addWidget(self.main_page)
        self.stack.addWidget(self.encrypt_page)
        self.stack.addWidget(self.attack_page)

    # MAIN PAGE
    def create_main_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Loren Criptum")
        title.setStyleSheet(
            "font-size: 36px; font-weight: bold; color: #00e676; text-align: center; margin-bottom: 20px;"
        )
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Buttons to navigate
        button_encrypt = QPushButton("Botón 1 (Encriptar)")
        button_encrypt.setStyleSheet(self.button_style())
        button_attack = QPushButton("Botón 2 (Atacar)")
        button_attack.setStyleSheet(self.button_style())

        button_encrypt.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        button_attack.clicked.connect(lambda: self.stack.setCurrentIndex(2))

        layout.addWidget(button_encrypt)
        layout.addWidget(button_attack)
        layout.addStretch()

        page.setLayout(layout)
        return page

    # ENCRYPT PAGE
    def create_encrypt_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        # Title
        title = QLabel("Loren Criptum - Encriptar")
        title.setStyleSheet(
            "font-size: 28px; font-weight: bold; color: #00e676; text-align: center; margin-bottom: 20px;"
        )
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Input Fields
        input_label = QLabel("Escriba su frase:")
        input_label.setStyleSheet("font-size: 16px; margin-bottom: 5px;")
        self.input_field = QLineEdit()
        self.input_field.setStyleSheet(
            "padding: 10px; font-size: 14px; border: 1px solid #555; border-radius: 5px;"
        )
        layout.addWidget(input_label)
        layout.addWidget(self.input_field)

        # Key Field
        key_label = QLabel("Escriba la clave de cifrado:")
        key_label.setStyleSheet("font-size: 16px; margin-top: 10px;")
        self.key_field = QLineEdit()
        self.key_field.setStyleSheet(
            "padding: 10px; font-size: 14px; border: 1px solid #555; border-radius: 5px;"
        )
        self.key_field.setPlaceholderText("Ingrese un número para la clave")
        layout.addWidget(key_label)
        layout.addWidget(self.key_field)

        # Output Fields
        output_label = QLabel("Texto encriptado:")
        output_label.setStyleSheet("font-size: 16px; margin-top: 10px;")
        self.output_field = QLabel("---")
        self.output_field.setStyleSheet("font-size: 16px; color: #00bcd4; font-weight: bold;")
        layout.addWidget(output_label)
        layout.addWidget(self.output_field)

        decrypted_label = QLabel("Texto desencriptado:")
        decrypted_label.setStyleSheet("font-size: 16px; margin-top: 10px;")
        self.decrypted_field = QLabel("---")
        self.decrypted_field.setStyleSheet("font-size: 16px; color: #ff9800; font-weight: bold;")
        layout.addWidget(decrypted_label)
        layout.addWidget(self.decrypted_field)

        # Buttons Grid
        buttons_layout = QHBoxLayout()
        left_buttons = QVBoxLayout()
        right_buttons = QVBoxLayout()
        
        firstmethods = ["1. Desplazamiento", "2. Multiplicativo", "3. Afín", "4. Sustitución", "5. RSA", "????"]
        funcs = [self.despla, self.multi, self.afin, self.susti, self.rsa]
        secondmethods = ["6. Vigenere", "7. Hill", "8. Permutaciones en Bloque", "9. Claves en Cadena", "10. Autoclave"]
        funcs2 = [self.vige, self.hill, self.permu, self.clave, self.autocla]

        for i, func in enumerate(funcs, start=1):
            button = QPushButton(f"{firstmethods[i-1]}")
            button.setStyleSheet(self.button_style())
            left_buttons.addWidget(button)

            button.clicked.connect(func)

        for i in range(6, 11):
            button = QPushButton(f"{secondmethods[i-6]}")
            button.setStyleSheet(self.button_style())
            right_buttons.addWidget(button)

        buttons_layout.addLayout(left_buttons)
        buttons_layout.addLayout(right_buttons)

        layout.addLayout(buttons_layout)

        # Back Button
        button_back = QPushButton("Volver")
        button_back.setStyleSheet(self.button_style())
        button_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))

        layout.addWidget(button_back)
        layout.setAlignment(Qt.AlignTop)
        page.setLayout(layout)
        return page

    # ATTACK PAGE
    def create_attack_page(self):
        page = QWidget()
        layout = QVBoxLayout()

        # Título
        title = QLabel("Loren Criptum - Atacar")
        title.setStyleSheet(
            "font-size: 28px; font-weight: bold; color: #ff5252; text-align: center; margin-bottom: 20px;"
        )
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Campo de texto cifrado
        input_label = QLabel("Texto cifrado:")
        input_label.setStyleSheet("font-size: 16px; margin-bottom: 5px;")
        self.input_field_attack = QLineEdit()
        self.input_field_attack.setStyleSheet(
            "padding: 10px; font-size: 14px; border: 1px solid #555; border-radius: 5px;"
        )
        layout.addWidget(input_label)
        layout.addWidget(self.input_field_attack)

        # Campo para clave
        key_label = QLabel("Clave de descifrado:")
        key_label.setStyleSheet("font-size: 16px; margin-bottom: 5px;")
        self.key_field_attack = QLineEdit()
        self.key_field_attack.setStyleSheet(
            "padding: 10px; font-size: 14px; border: 1px solid #555; border-radius: 5px;"
        )
        self.key_field_attack.setPlaceholderText("Ingrese la clave (un número)")
        layout.addWidget(key_label)
        layout.addWidget(self.key_field_attack)

        # Botón para descifrado multiplicativo
        multiplicative_button = QPushButton("Descifrado Multiplicativo")
        multiplicative_button.setStyleSheet(self.button_style())
        multiplicative_button.clicked.connect(self.decrypt_multiplicative)
        layout.addWidget(multiplicative_button)

        # Campo de texto descifrado
        decrypted_label = QLabel("Texto descifrado:")
        decrypted_label.setStyleSheet("font-size: 16px; margin-top: 10px;")
        self.decrypted_field_attack = QLabel("---")
        self.decrypted_field_attack.setStyleSheet("font-size: 16px; color: #00bcd4; font-weight: bold;")
        layout.addWidget(decrypted_label)
        layout.addWidget(self.decrypted_field_attack)

        # Botón para análisis de Brauer
        brauer_button = QPushButton("Análisis de Brauer")
        brauer_button.setStyleSheet(self.button_style())
        brauer_button.clicked.connect(self.perform_brauer_analysis)
        layout.addWidget(brauer_button)

        # Botón para volver
        button_back = QPushButton("Volver")
        button_back.setStyleSheet(self.button_style())
        button_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        layout.addWidget(button_back)

        layout.setAlignment(Qt.AlignTop)
        page.setLayout(layout)
        return page

    def despla():
        return

    def multi(self):
        # Cifra un texto usando el cifrado multiplicativo.
        alphabet_size = 26
        text = self.input_field.text().lower()
        encrypted_text = ""

        # Obtener la clave ingresada por el usuario
        try:
            key = int(self.key_field.text())
            if gcd(key, alphabet_size) != 1:
                self.output_field.setText("Clave inválida: no es coprima con 26.")
                return
        except ValueError:
            self.output_field.setText("Clave inválida: ingrese un número.")
            return

        for char in text:
            if char.isalpha():  # Solo cifrar letras
                # Convertir el carácter a un número (a=0, b=1, ..., z=25)
                char_num = ord(char) - ord('a')
                # Aplicar el cifrado multiplicativo
                encrypted_num = (char_num * key) % alphabet_size
                # Convertir de vuelta a carácter
                encrypted_char = chr(encrypted_num + ord('a'))
                encrypted_text += encrypted_char
            else:
                # Mantener otros caracteres sin cifrar
                encrypted_text += char

        # Mostrar el texto encriptado en el campo de salida
        self.output_field.setText(encrypted_text)


    def afin(self):
    # Obtener texto de entrada y clave
        text = self.input_field.text()
        key = self.key_field.text()
        
        try:
            a = -1
            b = -1
            a_str = ""
            b_str = ""
            i = 0
            
            # Parsear la clave
            while i < len(key) and key[i] != ' ':
                if key[i].isdigit():
                    a_str += key[i]
                    i += 1
                else:
                    self.output_field.setText("Clave inválida: a y b deben ser enteros y a coprimo con 26.")
                    return
            
            i += 1  # Saltar el espacio
            while i < len(key):
                if key[i].isdigit():
                    b_str += key[i]
                    i += 1
                else:
                    self.output_field.setText("Clave inválida: a y b deben ser enteros y a coprimo con 26.")
                    return
            
            a = int(a_str) % 26
            b = int(b_str) % 26

            if gcd(a, 26) != 1:
                self.output_field.setText("Clave inválida: a no es coprimo con 26.")
                return

            # Cifrar el texto
            ciphertext = ""
            for c in text:
                if c.isalpha():
                    if c.islower():
                        ciphertext += chr(((ord(c) - ord('a')) * a + b) % 26 + ord('a'))
                    else:
                        ciphertext += chr(((ord(c) - ord('A')) * a + b) % 26 + ord('A'))
                else:
                    ciphertext += c

            # Mostrar el texto cifrado
            self.output_field.setText(ciphertext)

        except Exception as e:
            self.output_field.setText(f"Error: {str(e)}")

    
    def susti(self):
    # Obtener texto de entrada y clave
        text = self.input_field.text()
        key = self.key_field.text()

        try:
            # Validar que la clave sea una permutación del alfabeto
            if len(key) != 26 or not all(c.isalpha() for c in key):
                self.output_field.setText("Clave inválida: Debe ser una permutación del alfabeto.")
                return

            # Crear mapeos para letras minúsculas y mayúsculas
            key_low = key.lower()
            key_up = key.upper()
            low_map = {chr(ord('a') + i): key_low[i] for i in range(26)}
            up_map = {chr(ord('A') + i): key_up[i] for i in range(26)}

            # Cifrar el texto
            ciphertext = ""
            for c in text:
                if c.isalpha():
                    if c.islower():
                        ciphertext += low_map[c]
                    else:
                        ciphertext += up_map[c]
                else:
                    ciphertext += c  # Preservar caracteres no alfabéticos

            # Mostrar el texto cifrado
            self.output_field.setText(ciphertext)

        except Exception as e:
            self.output_field.setText(f"Error: {str(e)}")

    
    def rsa(self):
        # Obtener la entrada del usuario
        try:
            p = int(self.key_field.text().split(',')[0])  # Primer número primo
            q = int(self.key_field.text().split(',')[1])  # Segundo número primo
            l = int(self.key_field.text().split(',')[2])  # Límite para buscar j
        except (ValueError, IndexError):
            self.output_field.setText("Error: Ingrese p, q y l separados por comas.")
            return

        texto = self.input_field.text().lower()
        if not texto:
            self.output_field.setText("Error: Ingrese un texto para cifrar.")
            return

        # Generar claves
        n = p * q
        z = (p - 1) * (q - 1)

        # Buscar k coprimos con z
        k_es = [i for i in range(2, z) if gcd(i, z) == 1]
        if not k_es:
            self.output_field.setText("Error: No se encontraron valores k coprimos con z.")
            return

        k = random.choice(k_es)

        # Buscar j que satisface la congruencia (1 + j * z) / k
        j_es = [j for j in range(l) if (1 + j * z) % k == 0]
        if not j_es:
            self.output_field.setText("Error: No se encontraron valores j válidos.")
            return

        j = random.choice(j_es)

        # Cifrar el mensaje
        encrypted_text = []
        for char in texto:
            if char.isalpha():
                M = ord(char) - ord('a') + 1
                C = pow(M, k, n)
                encrypted_text.append(C)
            else:
                encrypted_text.append(char)

        # Mostrar resultados
        self.output_field.setText(
            f"Cifrado: {' '.join(map(str, encrypted_text))}\nClaves: k={k}, n={n}, j={j}"
        )
    
    def vige(self):
        try:
            # Obtener texto y clave del usuario
            plaintext = self.input_field.text()
            key = self.key_field.text()

            # Validar clave
            if not all(c.isalpha() for c in key):
                self.output_field.setText("Clave inválida: debe contener solo caracteres alfabéticos.")
                return
            
            if len(plaintext) < len(key):
                self.output_field.setText("Texto inválido: no debe ser más corto que la clave.")
                return

            # Crear versiones de clave en minúsculas y mayúsculas
            low_key = key.lower()
            up_key = key.upper()

            ciphertext = []
            m = len(key)

            # Proceso de cifrado
            for i in range(len(plaintext)):
                char = plaintext[i]
                if char.isalpha():
                    if char.islower():
                        offset = (ord(char) - ord('a') + ord(low_key[i % m]) - ord('a')) % 26
                        ciphertext.append(chr(offset + ord('a')))
                    else:
                        offset = (ord(char) - ord('A') + ord(up_key[i % m]) - ord('A')) % 26
                        ciphertext.append(chr(offset + ord('A')))
                else:
                    ciphertext.append(char)  # Conservar caracteres no alfabéticos

            # Mostrar el texto cifrado
            self.output_field.setText(''.join(ciphertext))
        
        except Exception as e:
            self.output_field.setText(f"Error: {str(e)}")
    
    def hill(self):

        def to_int(char):
            return ord(char.upper()) - ord('A')

        def to_str(num):
            return chr(num + ord('A'))

        def mod_inverse(a, m):
            try:
                return pow(a, -1, m)
            except ValueError:
                return None

        try:
            # Obtener texto y clave del usuario
            plaintext = self.input_field.text().replace(" ", "").upper()
            key = self.key_field.text().upper()

            # Validar clave
            dim = sqrt(len(key))
            if not dim.is_integer():
                self.output_field.setText("Clave inválida: no es una matriz cuadrada.")
                return

            dim = int(dim)
            if len(plaintext) % dim != 0:
                self.output_field.setText(f"Texto inválido: el tamaño debe ser múltiplo de {dim}.")
                return

            # Crear matriz clave
            key_matrix = np.array(list(key)).reshape(dim, dim)
            key_matrix = np.vectorize(to_int)(key_matrix)

            # Validar que la clave sea modularmente invertible
            det = int(Matrix(key_matrix).det())
            mod = 26
            if gcd(det, mod) != 1:
                self.output_field.setText("Clave inválida: no es modularmente invertible.")
                return

            # Cifrar texto
            plaintext_vector = np.vectorize(to_int)(np.array(list(plaintext)))
            plaintext_vector = plaintext_vector.reshape(dim, -1)

            cipher_matrix = np.dot(key_matrix, plaintext_vector) % mod
            cipher_text = ''.join(np.vectorize(to_str)(cipher_matrix.flatten()))

            # Mostrar el texto cifrado
            self.output_field.setText(cipher_text)

        except Exception as e:
            self.output_field.setText(f"Error: {str(e)}")

    def permu():
        return

    def clave():
        return
    
    def autocla():
        return

    def decrypt_multiplicative(self):
        # Obtener el texto cifrado y la clave
        encrypted_text = self.input_field_attack.text()
        try:
            key = int(self.key_field_attack.text())  # Leer la clave desde el campo de ataque
        except ValueError:
            self.decrypted_field_attack.setText("Clave inválida. Debe ser un número entero.")
            return

        # Verificar que la clave sea coprima con 26
        if gcd(key, 26) != 1:
            self.decrypted_field_attack.setText("Clave inválida. Debe ser coprima con 26.")
            return

        # Calcular el inverso modular de la clave
        try:
            key_inverse = pow(key, -1, 26)
        except ValueError:
            self.decrypted_field_attack.setText("No se pudo calcular el inverso modular.")
            return

        # Descifrar el texto
        decrypted_text = ""
        for char in encrypted_text:
            if char.isalpha():
                # Convertir a índice (a=0, ..., z=25)
                char_num = ord(char.lower()) - ord('a')
                # Aplicar descifrado multiplicativo
                decrypted_num = (char_num * key_inverse) % 26
                decrypted_char = chr(decrypted_num + ord('a'))
                # Conservar mayúsculas y minúsculas
                decrypted_text += decrypted_char.upper() if char.isupper() else decrypted_char
            else:
                # Mantener caracteres no alfabéticos sin cambios
                decrypted_text += char

        # Mostrar el texto descifrado
        self.decrypted_field_attack.setText(decrypted_text)


    def perform_brauer_analysis(self):
        # Obtener texto de entrada
        text = self.input_field_attack.text()
        if not text:
            QMessageBox.warning(self, "Advertencia", "Por favor, ingresa un texto para analizar.")
            return

        # Llamar a la función de análisis de Brauer
        try:
            iniciar_visualizacion(text)  # Asegúrate de que no usa QApplication.exec_()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Se produjo un error durante el análisis: {str(e)}")

    # BUTTON STYLE
    def button_style(self):
        return (
            "QPushButton {"
            "background-color: #009688; color: white; font-size: 14px; border-radius: 10px; padding: 12px 20px;"
            "box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.3);"
            "}"
            "QPushButton:hover {"
            "background-color: #00796b;"
            "}"
            "QPushButton:pressed {"
            "background-color: #004d40;"
            "}"
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LorenCriptum()
    window.show()
    sys.exit(app.exec_())
