# app/codesmell_test.py
from math import *  # CODE SMELL: Wildcard import
import sys
import os

# VULNERABILIDAD / SECURITY HOTSPOT: Credenciales hardcodeadas
SUPER_SECRET_TOKEN = "ghp_FakeToken1234567890abcdefghijklmnopqrstuvwxyz"
DB_PASS = "admin1234"
JWT_KEY = "mi_clave_secreta_super_debil"

def query_user_unsafe(username: str):
    # VULNERABILIDAD: SQL Injection directo (string interpolation)
    sql_query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{DB_PASS}'"
    print(f"Executing query: {sql_query}") # CODE SMELL: Uso de print en lugar de logger
    return sql_query

def complex_bad_function(a, b, c, d, e, f):
    # CODE SMELL: Demasiados parámetros
    # CODE SMELL: Alta complejidad cognitiva (nested ifs)
    if a > 0:
        if b < 10:
            if c == "test":
                for i in range(10):
                    if d == i:
                        print("Match d")
                        if e is not None:
                            if f == "admin":
                                # CODE SMELL: Variable no usada
                                unused_variable = 9999
                                return True
                            else:
                                return False
                        else:
                            return False
                    else:
                        pass
            else:
                return False
        else:
            return False
    else:
        return False

def dangerous_eval(user_input):
    # VULNERABILIDAD CRÍTICA: Código dinámico arbitrario (Remote Code Execution)
    return eval(user_input)

def blind_exception_catcher():
    # CODE SMELL: Captura ciega de excepciones sin registrar ni relanzar
    try:
        x = 1 / 0
    except Exception:
        pass

class BadClass:
    # CODE SMELL: Clase vacía o métodos estáticos sin usar self
    def print_hello(self):
        print("Hello")
        
    def math_op(self, x, y):
        # CODE SMELL: No usa self
        return x + y
