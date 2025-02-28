import os, sys
import ctypes
_dir = os.path.dirname(os.path.abspath(__file__))
_lib = ctypes.CDLL(os.path.join(_dir, "truefa_crypto.dll"))
# Import all symbols from the rust module
from truefa_crypto import *
