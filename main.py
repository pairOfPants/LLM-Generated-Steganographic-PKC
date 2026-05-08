# This is the core file for each function
# -- Imports --
import haslib 

# Top Table 
TOP_F_TABLE = {
    (16, 1): 16,  (16, 2): 17,  (16, 3): 25,  (16, 4): 29,
    (32, 1): 32,  (32, 2): 34,  (32, 3): 49,  (32, 4): 58,
    (48, 1): 51,  (48, 2): 73,  (48, 3): 87,  (48, 4): 179,
    (64, 1): 68,  (64, 2): 97,  (64, 3): 116, (64, 4): 239,
    (96, 1): 102, (96, 2): 146, (96, 3): 174, (96, 4): 358,
    (128, 1): 136,(128, 2): 194,(128, 3): 232,(128, 4): 477
}

# PRF (SHAKE128)
# Create SHAKE128 hash object 
def PRF()
maraca = haslib.shake_128()

# Update hash object 


# Embedder LLM function
# -- Parameters -- 
# LLM: name of specific LLM model
# TOPIC: Topic of story generated
# Story0: Possible previous story 
# T0: Starting value for temperature 
# k0: inital value for the top k0 tokens w/ top k0 Probs
# C: sequence = [C0, C1,..., C_(n-1)] of chars from some sets S1,...,S4
# b: sequence of int = [b0,b1,...,b_(n-1)] {same number n as C}
