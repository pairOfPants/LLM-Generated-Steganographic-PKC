SALT: bytes = b"CHIP-LLM-PKC-v1"
TEMPERATURE: float = 0.7
TOP_K: int = 40
SECURITY_LEVEL: int = 128

#Algorithm 2 specific constants
PBKDF2_iterations: int = 600000
NONCE_SIZE: int = 12
CHUNK_SIZE: int = 5
OFFSET_DISTANCE: int = 32
ASSOCIATED_DATA: bytes = b""
H4 = [(0, ' '), (1, 'E'), (2, 'T'), (3, 'A'), 
      (4, 'O'), (5, 'N'), (6, 'I'), (7, 'S'), 
      (8, 'R'), (9, 'H'), (10, 'D'), (11, 'L'), 
      (12, 'U'), (13, 'C'), (14, 'M'), (15, 'F')]

H5 = [(0, ' '), (1, 'E'), (2, 'T'), (3, 'A'), 
      (4, 'O'), (5, 'N'), (6, 'I'), (7, 'S'), 
      (8, 'R'), (9, 'H'), (10, 'D'), (11, 'L'), 
      (12, 'U'), (13, 'C'), (14, 'M'), (15, 'F'),
      (16, 'W'), (17, ','), (18, 'G'), (19, 'Y'), 
      (20, 'P'), (21, 'B'), (22, '.'), (23, 'V'), 
      (24, 'K'), (25, '-'), (26, 'X'), (27, 'J'),
      (28, 'Q'), (29, '!'), (30, 'Z'), (31, '?')]